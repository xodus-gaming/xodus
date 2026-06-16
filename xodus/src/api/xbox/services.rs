use rsa::pkcs1::der::Sequence;
use xal::cvlib::CorrelationVector;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MyGames {
    result: MyGamesResults,
    product_summaries: ProductSummary,
    product_prices: std::collections::HashMap<String, ProductPrice>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MyGamesResults {
    title: String,
    product_ids: Vec<String>,
    total_item_count: u32,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProductSummary {
    #[serde(flatten)]
    items: std::collections::HashMap<String, ProductSummaryItem>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProductSummaryItem {
    alternate_ids: Vec<AlternateId>,
    average_rating: f64,
    //badges
    //box_art_image
    //bundled_product_ids
    capabilities: Vec<String>,
    categories: Vec<String>,
    minimum_user_age: u32,
    description: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    has_add_ons: Option<bool>,
    //hero_image
    #[serde(skip_serializing_if = "Option::is_none")]
    included_in_pcgp: Option<bool>,
    included_in_ultimate: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    included_in_eaplay: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    package_family_name: Option<String>,
    //poster_image
    product_kind: String,
    publisher_name: String,
    rating_count: u32,
    release_date: String,
    short_description: String,
    short_title: String,
    //tile_image
    title: String,
    ttl: String,
    available_platforms: Vec<String>,
    #[serde(rename = "isXPA", skip_serializing_if = "Option::is_none")]
    is_xpa: Option<bool>,
    //third_party_streaming
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AlternateId {
    id_type: String,
    value: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProductPrice {
    msrp: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    sale_price: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    discount_percentage: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    discount_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    after_price_text: Option<String>,
    #[serde(rename = "strikethroughMSRP")]
    strikethrough_msrp: bool,
    has_x_price_storewide_offer: bool,
    ttl: String,
}

pub async fn get_library(
    client: &reqwest::Client,
    token: String,
    xsts_header: String
)  -> reqwest::Result<MyGames> {

    let cv = CorrelationVector::new();

    let resp = client
        .get("https://beige.xboxservices.com/pcgafd/mygames")
        .query(&[("market", "AU"), ("language", "en-US"), ("appVersion", "2606.1001.27.0")]) // TODO
        .header("x-ms-api-version", "1.2")
        .header("x-ms-authorization-social", xsts_header)
        .header("Authorization", token)
        .header("ms-cv", cv.to_string())
        .send()
        .await?
        .error_for_status()?;

    let text = resp.text().await?;

    let parsed = serde_json::from_str::<MyGames>(&text).unwrap();

    return Ok(parsed);
}
