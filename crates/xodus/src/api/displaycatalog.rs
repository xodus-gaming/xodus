use crate::models::displaycatalog::DisplayCatalogProductsResponse;

pub async fn find_products_by_id(
    client: &reqwest::Client,
    product: String,
    market: String,
    languages: Vec<String>,
) -> reqwest::Result<DisplayCatalogProductsResponse> {
    let langs = languages.join(",");
    let response = client.get(format!("https://displaycatalog.mp.microsoft.com/v7.0/products/{product}?market={market}&languages={langs}")).send().await?;
    let response = response.error_for_status()?;
    response.json().await
}
