//! Provider-neutral invoice extraction. Structured XML is always attempted
//! before Azure so UBL/CII documents do not consume metered OCR calls.

use rust_decimal::Decimal;
use serde_json::{Value, json};

use crate::domain::IntegrationError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExtractionSource {
    Structured,
    Azure,
}

pub fn structured(source: &[u8]) -> Option<Value> {
    if source.starts_with(b"%PDF-") {
        let options = lopdf::LoadOptions::with_max_decompressed_size(4 * 1024 * 1024);
        let document = lopdf::Document::load_mem_with_options(source, options).ok()?;
        for object in document.objects.values() {
            let lopdf::Object::Stream(stream) = object else {
                continue;
            };
            let Ok(candidate) = stream.decompressed_content_with_limit(4 * 1024 * 1024) else {
                continue;
            };
            if let Some(invoice) = structured_xml(&candidate) {
                return Some(invoice);
            }
        }
        return None;
    }
    structured_xml(source)
}

fn structured_xml(source: &[u8]) -> Option<Value> {
    let text = std::str::from_utf8(source).ok()?;
    let is_ubl = text.contains("Invoice")
        && (text.contains("urn:oasis:names:specification:ubl") || text.contains("<Invoice"));
    let is_cii = text.contains("CrossIndustryInvoice") || text.contains("CrossIndustryDocument");
    if !is_ubl && !is_cii {
        return None;
    }
    let supplier_name = first(text, &["RegistrationName", "Name", "SellerTradeParty"]);
    let supplier_vat = first(text, &["CompanyID", "SpecifiedTaxRegistration"]);
    let invoice_number = first(text, &["ID"]);
    let invoice_date = first(text, &["IssueDate", "IssueDateTime"]);
    let currency = first(text, &["DocumentCurrencyCode", "InvoiceCurrencyCode"])
        .unwrap_or_else(|| "EUR".into());
    let untaxed = decimal(first(text, &["TaxExclusiveAmount", "LineTotalAmount"]));
    let tax = decimal(first(text, &["TaxAmount"]));
    let total = decimal(first(
        text,
        &["TaxInclusiveAmount", "GrandTotalAmount", "PayableAmount"],
    ));
    Some(json!({
        "supplier_name":supplier_name,"supplier_vat":supplier_vat,
        "invoice_number":invoice_number,"invoice_date":normalize_date(invoice_date),
        "currency":currency,"untaxed_amount":untaxed,"tax_amount":tax,"total_amount":total,
        "lines":[{"description":"Structured supplier invoice","quantity":"1","unit_price":untaxed,"account_code":""}]
    }))
}

pub fn normalize_azure(result: &Value) -> Result<(Value, Value, i64), IntegrationError> {
    let document = result
        .pointer("/documents/0")
        .ok_or(IntegrationError::ContractDrift)?;
    let fields = document
        .get("fields")
        .and_then(Value::as_object)
        .ok_or(IntegrationError::ContractDrift)?;
    let get = |name: &str| fields.get(name);
    let supplier_name = string_field(get("VendorName"));
    let supplier_vat = string_field(get("VendorTaxId"));
    let invoice_number = string_field(get("InvoiceId"));
    let invoice_date = string_field(get("InvoiceDate"));
    let due_date = string_field(get("DueDate"));
    let (total, currency) = currency_field(get("InvoiceTotal"));
    let (untaxed, _) = currency_field(get("SubTotal"));
    let (tax, _) = currency_field(get("TotalTax"));
    let mut lines = Vec::new();
    if let Some(items) = get("Items")
        .and_then(|v| v.get("valueArray"))
        .and_then(Value::as_array)
    {
        for item in items {
            let object = item.get("valueObject").and_then(Value::as_object);
            let field = |name: &str| object.and_then(|o| o.get(name));
            let quantity = number_field(field("Quantity")).unwrap_or(Decimal::ONE);
            let (unit_price, _) = currency_field(field("UnitPrice"));
            let (line_amount, _) = currency_field(field("Amount"));
            lines.push(json!({
                "description":string_field(field("Description")).unwrap_or_else(||"Invoice line".into()),
                "quantity":quantity.to_string(),"unit_price":unit_price,"account_code":"",
                "line_amount":line_amount,
                "product_default_code":string_field(field("ProductCode")),
                "tax_rate":number_field(field("TaxRate")).map(|v|v.to_string())
            }));
        }
    }
    if lines.is_empty() {
        lines.push(json!({"description":"Captured supplier invoice","quantity":"1","unit_price":untaxed,"account_code":""}));
    }
    let confidence = fields
        .iter()
        .map(|(name, value)| {
            (
                name.clone(),
                value.get("confidence").cloned().unwrap_or(Value::Null),
            )
        })
        .collect::<serde_json::Map<_, _>>();
    let pages = result
        .get("pages")
        .and_then(Value::as_array)
        .map_or(1, |p| p.len().max(1)) as i64;
    Ok((
        json!({
            "supplier_name":supplier_name,"supplier_vat":supplier_vat,"invoice_number":invoice_number,
            "invoice_date":invoice_date,"due_date":due_date,"currency":currency.unwrap_or_else(||"EUR".into()),
            "untaxed_amount":untaxed,"tax_amount":tax,"total_amount":total,"lines":lines
        }),
        Value::Object(confidence),
        pages,
    ))
}

pub fn requires_review(invoice: &Value, confidence: &Value) -> bool {
    let required = [
        "supplier_name",
        "invoice_number",
        "invoice_date",
        "currency",
        "total_amount",
    ];
    if required
        .iter()
        .any(|key| invoice.get(key).is_none_or(Value::is_null))
    {
        return true;
    }
    confidence.as_object().is_some_and(|map| {
        map.values()
            .filter_map(Value::as_f64)
            .any(|score| score < 0.75)
    })
}

fn string_field(value: Option<&Value>) -> Option<String> {
    let value = value?;
    for key in ["valueString", "valueDate", "content"] {
        if let Some(text) = value
            .get(key)
            .and_then(Value::as_str)
            .filter(|s| !s.trim().is_empty())
        {
            return Some(text.trim().into());
        }
    }
    None
}
fn number_field(value: Option<&Value>) -> Option<Decimal> {
    let value = value?;
    if let Some(parsed) = content_decimal(value) {
        return Some(parsed);
    }
    value
        .get("valueNumber")
        .and_then(Value::as_f64)
        .and_then(Decimal::from_f64_retain)
        .or_else(|| string_field(Some(value)).and_then(|s| s.replace(',', ".").parse().ok()))
}
fn currency_field(value: Option<&Value>) -> (String, Option<String>) {
    let Some(value) = value else {
        return ("0".into(), None);
    };
    let object = value.get("valueCurrency").unwrap_or(value);
    let amount = content_decimal(value)
        .or_else(|| {
            object
                .get("amount")
                .and_then(Value::as_f64)
                .and_then(Decimal::from_f64_retain)
        })
        .unwrap_or(Decimal::ZERO)
        .to_string();
    let currency = object
        .get("currencyCode")
        .and_then(Value::as_str)
        .map(str::to_owned);
    (amount, currency)
}

fn content_decimal(value: &Value) -> Option<Decimal> {
    let content = value.get("content")?.as_str()?.trim();
    let mut numeric = content
        .chars()
        .filter(|character| character.is_ascii_digit() || matches!(character, '-' | ',' | '.'))
        .collect::<String>();
    if numeric.is_empty() {
        return None;
    }
    match (numeric.rfind(','), numeric.rfind('.')) {
        (Some(comma), Some(dot)) if comma > dot => {
            numeric = numeric.replace('.', "").replace(',', ".");
        }
        (Some(_), Some(_)) => {
            numeric = numeric.replace(',', "");
        }
        (Some(_), None) => numeric = numeric.replace(',', "."),
        _ => {}
    }
    numeric.parse().ok()
}
fn decimal(value: Option<String>) -> String {
    value
        .and_then(|v| v.replace(',', ".").parse::<Decimal>().ok())
        .unwrap_or(Decimal::ZERO)
        .to_string()
}
fn normalize_date(value: Option<String>) -> Option<String> {
    value
        .map(|v| v.chars().filter(char::is_ascii_digit).collect::<String>())
        .and_then(|v| {
            if v.len() >= 8 {
                Some(format!("{}-{}-{}", &v[0..4], &v[4..6], &v[6..8]))
            } else {
                None
            }
        })
}
fn first(text: &str, names: &[&str]) -> Option<String> {
    for name in names {
        let needle = format!("{name}>");
        let mut from = 0;
        while let Some(relative) = text[from..].find(&needle) {
            let marker_start = from + relative;
            let open = text[..marker_start].rfind('<')?;
            if text.as_bytes().get(open + 1) != Some(&b'/') {
                let content_start = marker_start + needle.len();
                if let Some(close_relative) = text[content_start..].find('<') {
                    let value = text[content_start..content_start + close_relative].trim();
                    if !value.is_empty() {
                        return Some(value.into());
                    }
                }
            }
            from = marker_start + needle.len();
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn ubl_is_detected_without_azure() {
        let xml=br#"<Invoice xmlns="urn:oasis:names:specification:ubl:schema:xsd:Invoice-2"><ID>INV-1</ID><IssueDate>2026-08-01</IssueDate><DocumentCurrencyCode>EUR</DocumentCurrencyCode><TaxExclusiveAmount>10.00</TaxExclusiveAmount><TaxAmount>2.00</TaxAmount><PayableAmount>12.00</PayableAmount></Invoice>"#;
        let value = structured(xml).unwrap();
        assert_eq!(value["invoice_number"], "INV-1");
        assert_eq!(value["total_amount"], "12.00");
    }

    #[test]
    fn factur_x_embedded_stream_is_detected_without_azure() {
        let xml = br#"<rsm:CrossIndustryInvoice xmlns:rsm="urn:un:unece:uncefact:data:standard:CrossIndustryInvoice:100"><rsm:ID>FX-9</rsm:ID><rsm:IssueDateTime>20260801</rsm:IssueDateTime><rsm:InvoiceCurrencyCode>EUR</rsm:InvoiceCurrencyCode><rsm:GrandTotalAmount>42.00</rsm:GrandTotalAmount></rsm:CrossIndustryInvoice>"#;
        let mut document = lopdf::Document::with_version("1.7");
        document.add_object(lopdf::Stream::new(
            lopdf::dictionary! {"Type" => "EmbeddedFile"},
            xml.to_vec(),
        ));
        let mut pdf = Vec::new();
        document.save_to(&mut pdf).unwrap();
        let invoice = structured(&pdf).expect("embedded CII");
        assert_eq!(invoice["invoice_number"], "FX-9");
        assert_eq!(invoice["total_amount"], "42.00");
    }

    #[test]
    fn azure_french_decimal_content_takes_precedence_over_scaled_numeric_value() {
        let result = json!({
            "documents": [{"fields": {
                "VendorName": {"content": "Fournisseur"},
                "InvoiceId": {"content": "FA-1"},
                "InvoiceDate": {"valueDate": "2026-08-08"},
                "InvoiceTotal": {"content": "64,55 EUR", "valueCurrency": {"amount": 64.55, "currencyCode": "EUR"}},
                "SubTotal": {"content": "53,79 EUR", "valueCurrency": {"amount": 53.79, "currencyCode": "EUR"}},
                "TotalTax": {"content": "10,76 EUR", "valueCurrency": {"amount": 10.76, "currencyCode": "EUR"}},
                "Items": {"valueArray": [{"valueObject": {
                    "Description": {"content": "Grès"},
                    "Quantity": {"content": "12,500", "valueNumber": 12500},
                    "UnitPrice": {"content": "1,170 EUR", "valueCurrency": {"amount": 1170, "currencyCode": "EUR"}},
                    "Amount": {"content": "14,63 EUR", "valueCurrency": {"amount": 1463, "currencyCode": "EUR"}}
                }}]}
            }}],
            "pages": [{}]
        });

        let (invoice, _, _) = normalize_azure(&result).unwrap();

        assert_eq!(invoice["lines"][0]["quantity"], "12.500");
        assert_eq!(invoice["lines"][0]["unit_price"], "1.170");
        assert_eq!(invoice["lines"][0]["line_amount"], "14.63");
    }
}
