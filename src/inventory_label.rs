//! Provider-neutral normalization for inventory product-label extraction.
//! Provider text is evidence only; stock mutations remain an Odoo user action.

use regex::Regex;
use serde_json::{Value, json};

use crate::domain::IntegrationError;

pub fn normalize_vision(result: &Value, ocr_tokens: &Value) -> Result<Value, IntegrationError> {
    if !matches!(
        result.get("status").and_then(Value::as_str),
        Some("candidates" | "unknown")
    ) {
        return Err(IntegrationError::ContractDrift);
    }
    let products = result
        .get("product_candidates")
        .and_then(Value::as_array)
        .filter(|items| items.len() <= 5)
        .ok_or(IntegrationError::ContractDrift)?;
    let lots = result
        .get("lot_candidates")
        .and_then(Value::as_array)
        .filter(|items| items.len() <= 5)
        .ok_or(IntegrationError::ContractDrift)?;
    let warnings = bounded_strings(result.get("warnings"), 10, 300)?;
    let deterministic_text = ocr_tokens
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|token| token.get("text").and_then(Value::as_str))
        .map(|text| text.to_ascii_lowercase())
        .collect::<Vec<_>>()
        .join(" ");
    let mut candidates = Vec::new();
    let mut clean_products = Vec::new();
    for item in products {
        let brand = bounded_string(item.get("brand"), 100)?;
        let sku = bounded_string(item.get("manufacturer_sku"), 100)?;
        let name = bounded_string(item.get("name"), 200)?;
        let pack = bounded_string(item.get("pack"), 100)?;
        let query = bounded_string(item.get("search_query"), 300)?;
        let evidence = bounded_strings(item.get("visible_evidence"), 10, 200)?;
        let confidence = bounded_confidence(item.get("confidence"))?;
        if brand.is_empty() && sku.is_empty() && name.is_empty() {
            return Err(IntegrationError::ContractDrift);
        }
        let label = [brand.as_str(), sku.as_str(), name.as_str(), pack.as_str()]
            .into_iter()
            .filter(|value| !value.is_empty())
            .collect::<Vec<_>>()
            .join(" ");
        clean_products.push(json!({"brand":brand,"manufacturer_sku":sku,"name":name,
            "pack":pack,"visible_evidence":evidence,"search_query":query,"confidence":confidence}));
        candidates.push(json!({"kind":"product","raw_value":label,
            "normalized_value":query,"source":"ai_suggestion","confidence":confidence,
            "explanation":format!("Visible text: {}. Suggested lookup: {query}", evidence.join(", ")),
            "grounding_state":"unverified"}));
    }
    let mut clean_lots = Vec::new();
    for item in lots {
        let raw = bounded_string(item.get("raw_value"), 100)?;
        let evidence = bounded_string(item.get("evidence_text"), 300)?;
        let asset_id = bounded_string(item.get("asset_id"), 64)?;
        let confidence = bounded_confidence(item.get("confidence"))?;
        let region = item
            .get("reported_region")
            .and_then(Value::as_array)
            .filter(|points| {
                points.len() == 4
                    && points.iter().all(|point| {
                        point
                            .as_f64()
                            .is_some_and(|value| (0.0..=1.0).contains(&value))
                    })
            })
            .ok_or(IntegrationError::ContractDrift)?
            .clone();
        if raw.is_empty() || evidence.is_empty() || asset_id.is_empty() {
            return Err(IntegrationError::ContractDrift);
        }
        let grounded = deterministic_text.contains(&raw.to_ascii_lowercase());
        clean_lots.push(
            json!({"raw_value":raw,"evidence_text":evidence,"asset_id":asset_id,
            "reported_region":region,"confidence":confidence}),
        );
        candidates.push(json!({"kind":"lot","raw_value":raw,"normalized_value":raw,
            "source":"ai_suggestion","confidence":confidence,"explanation":evidence,
            "reported_region":region,"grounding_state":if grounded{"grounded"}else{"unverified"}}));
    }
    Ok(
        json!({"status":result["status"],"product_candidates":clean_products,
        "lot_candidates":clean_lots,"warnings":warnings,"candidates":candidates}),
    )
}

fn bounded_string(value: Option<&Value>, maximum: usize) -> Result<String, IntegrationError> {
    value
        .and_then(Value::as_str)
        .filter(|text| text.len() <= maximum)
        .map(str::to_owned)
        .ok_or(IntegrationError::ContractDrift)
}

fn bounded_strings(
    value: Option<&Value>,
    count: usize,
    length: usize,
) -> Result<Vec<String>, IntegrationError> {
    let values = value
        .and_then(Value::as_array)
        .filter(|items| items.len() <= count)
        .ok_or(IntegrationError::ContractDrift)?;
    values
        .iter()
        .map(|item| bounded_string(Some(item), length))
        .collect()
}

fn bounded_confidence(value: Option<&Value>) -> Result<f64, IntegrationError> {
    value
        .and_then(Value::as_f64)
        .filter(|confidence| (0.0..=1.0).contains(confidence))
        .ok_or(IntegrationError::ContractDrift)
}

pub fn normalize_azure_read(result: &Value, asset_id: &str) -> Result<Value, IntegrationError> {
    let pages = result
        .get("pages")
        .and_then(Value::as_array)
        .ok_or(IntegrationError::ContractDrift)?;
    let mut tokens = Vec::new();
    let mut codes = Vec::new();
    for page in pages {
        let width = page.get("width").and_then(Value::as_f64).filter(|value| *value > 0.0);
        let height = page.get("height").and_then(Value::as_f64).filter(|value| *value > 0.0);
        for word in page
            .get("words")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .take(160_usize.saturating_sub(tokens.len()))
        {
            let content = word
                .get("content")
                .and_then(Value::as_str)
                .unwrap_or("")
                .trim();
            if content.is_empty() || content.len() > 256 {
                continue;
            }
            tokens.push(json!({
                "text": content,
                "confidence": word.get("confidence").and_then(Value::as_f64).unwrap_or(0.0).clamp(0.0, 1.0),
                "polygon": normalized_region(word.get("polygon"), width, height),
                "asset_id": asset_id,
            }));
        }
        for barcode in page
            .get("barcodes")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .take(20_usize.saturating_sub(codes.len()))
        {
            let value = barcode
                .get("value")
                .and_then(Value::as_str)
                .unwrap_or("")
                .trim();
            if !value.is_empty() && value.len() <= 512 {
                codes.push(json!({
                    "value": value,
                    "kind": barcode.get("kind").and_then(Value::as_str).unwrap_or("unknown"),
                    "confidence": barcode.get("confidence").and_then(Value::as_f64).unwrap_or(0.0).clamp(0.0, 1.0),
                    "polygon": normalized_region(barcode.get("polygon"), width, height),
                    "asset_id": asset_id,
                }));
            }
        }
    }
    let candidates = lot_candidates(&tokens);
    Ok(json!({"ocr_tokens": tokens, "codes": codes, "candidates": candidates}))
}

fn normalized_region(value: Option<&Value>, width: Option<f64>, height: Option<f64>) -> Value {
    let Some(points) = value.and_then(Value::as_array) else {
        return Value::Null;
    };
    let (Some(width), Some(height)) = (width, height) else {
        return Value::Null;
    };
    if points.len() < 4 || points.len() > 16 || points.len() % 2 != 0 {
        return Value::Null;
    }
    let coordinates = points.iter().map(Value::as_f64).collect::<Option<Vec<_>>>();
    let Some(coordinates) = coordinates else { return Value::Null };
    let xs = coordinates.iter().step_by(2).copied().collect::<Vec<_>>();
    let ys = coordinates.iter().skip(1).step_by(2).copied().collect::<Vec<_>>();
    let min_x = xs.iter().copied().fold(f64::INFINITY, f64::min) / width;
    let max_x = xs.iter().copied().fold(f64::NEG_INFINITY, f64::max) / width;
    let min_y = ys.iter().copied().fold(f64::INFINITY, f64::min) / height;
    let max_y = ys.iter().copied().fold(f64::NEG_INFINITY, f64::max) / height;
    if [min_x, min_y, max_x, max_y].iter().all(|value| (0.0..=1.0).contains(value)) {
        json!([min_x, min_y, max_x, max_y])
    } else {
        Value::Null
    }
}

fn lot_candidates(tokens: &[Value]) -> Vec<Value> {
    let marker = Regex::new(r"(?i)^(?:lot|batch|l)[\s:#.-]*([A-Z0-9][A-Z0-9._/-]{2,39})$")
        .expect("static lot marker regex");
    let standalone =
        Regex::new(r"^[A-Za-z0-9][A-Za-z0-9._/-]{2,39}$").expect("static lot value regex");
    let mut values = Vec::new();
    for (index, token) in tokens.iter().enumerate() {
        let text = token.get("text").and_then(Value::as_str).unwrap_or("");
        let captured = marker
            .captures(text)
            .and_then(|captures| captures.get(1).map(|value| value.as_str().to_owned()))
            .or_else(|| {
                if matches!(text.to_ascii_lowercase().as_str(), "lot" | "batch" | "l") {
                    tokens
                        .get(index + 1)
                        .and_then(|next| next.get("text"))
                        .and_then(Value::as_str)
                        .filter(|next| standalone.is_match(next))
                        .map(str::to_owned)
                } else {
                    None
                }
            });
        if let Some(raw) = captured {
            if values.iter().any(|item: &Value| {
                item.get("normalized_value") == Some(&Value::String(raw.clone()))
            }) {
                continue;
            }
            values.push(json!({
                "kind": "lot",
                "raw_value": raw,
                "normalized_value": raw,
                "source": "azure_read_lot_marker",
                "confidence": token.get("confidence").and_then(Value::as_f64).unwrap_or(0.0),
                "grounding_state": "grounded",
                "reported_region": token.get("polygon").cloned().unwrap_or(Value::Null),
            }));
        }
    }
    values
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn azure_words_produce_grounded_lot_candidate() {
        let normalized = normalize_azure_read(
            &json!({"pages":[{"words":[
                {"content":"LOT","confidence":0.99,"polygon":[0,0,1,0,1,1,0,1]},
                {"content":"001A-09","confidence":0.91,"polygon":[2,0,3,0,3,1,2,1]}
            ]}]}),
            "asset-1",
        )
        .unwrap();
        assert_eq!(normalized["candidates"][0]["raw_value"], "001A-09");
        assert_eq!(normalized["candidates"][0]["grounding_state"], "grounded");
    }

    #[test]
    fn vision_lot_is_unverified_without_matching_deterministic_text() {
        let result = json!({
            "status":"candidates",
            "product_candidates":[],
            "lot_candidates":[{"raw_value":"8O1B","evidence_text":"LOT 8O1B",
                "asset_id":"detail","reported_region":[0.1,0.2,0.4,0.3],"confidence":0.78}],
            "warnings":["O may be zero"]
        });
        let normalized = normalize_vision(&result, &json!([
            {"text":"LOT"},{"text":"801B"}
        ])).unwrap();
        assert_eq!(normalized["candidates"][0]["grounding_state"], "unverified");
        assert_eq!(normalized["candidates"][0]["raw_value"], "8O1B");
    }

    #[test]
    fn vision_schema_rejects_out_of_bounds_regions() {
        let result = json!({
            "status":"candidates","product_candidates":[],
            "lot_candidates":[{"raw_value":"LOT1","evidence_text":"LOT LOT1",
                "asset_id":"detail","reported_region":[0.1,0.2,1.4,0.3],"confidence":0.9}],
            "warnings":[]
        });
        assert!(normalize_vision(&result, &json!([])).is_err());
    }
}
