use serde::{Deserialize, Serialize};

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct DisplayCatalogProductsResponse {
    pub product: Product,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Product {
    pub last_modified_date: String,
    pub localized_properties: Vec<LocalizedProperty>,
    pub market_properties: Vec<MarketProperty>,
    pub product_a_schema: String,
    pub product_b_schema: String,
    pub product_id: String,
    pub properties: ProductProperties,
    pub alternate_ids: Vec<AlternateId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub domain_data_version: Option<String>,
    pub ingestion_source: String,
    pub is_microsoft_product: bool,
    pub preferred_sku_id: String,
    pub product_type: String,
    pub validation_data: ValidationData,
    pub merchandizing_tags: Vec<String>,
    #[serde(rename = "PartD")]
    pub part_d: String,
    pub sandbox_id: Option<String>,
    pub product_family: String,
    pub schema_version: String,
    #[serde(default)]
    pub is_sandboxed_product: bool,
    pub product_kind: String,
    pub product_policies: ProductPolicies,
    pub display_sku_availabilities: Vec<DisplaySkuAvailability>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct LocalizedProperty {
    pub developer_name: String,
    pub publisher_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub publisher_address: Option<String>,
    pub publisher_website_uri: String,
    pub support_uri: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub support_phone: Option<String>,
    #[serde(rename = "CMSVideos")]
    pub cms_videos: Vec<CMSVideo>,
    pub eligibility_properties: EligibilityProperties,
    pub franchises: Vec<String>,
    pub images: Vec<Image>,
    pub videos: Vec<String>,
    pub product_description: String,
    pub product_title: String,
    pub short_title: String,
    pub sort_title: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub friendly_title: Option<String>,
    pub short_description: String,
    pub search_titles: Vec<SearchTitle>,
    pub voice_title: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub render_group_details: Option<String>,
    pub product_display_ranks: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub interactive_model_config: Option<String>,
    pub interactive3_d_enabled: bool,
    pub language: String,
    pub markets: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct CMSVideo {
    #[serde(rename = "DASH")]
    pub dash: String,
    #[serde(rename = "HLS")]
    pub hls: String,
    #[serde(rename = "CMS", skip_serializing_if = "Option::is_none")]
    pub cms: Option<String>,
    #[serde(rename = "CC", skip_serializing_if = "Option::is_none")]
    pub cc: Option<String>,
    pub video_purpose: String,
    pub height: i32,
    pub width: i32,
    pub audio_encoding: String,
    pub video_encoding: String,
    pub video_position_info: String,
    pub caption: Option<String>,
    pub file_size_in_bytes: i64,
    pub preview_image: PreviewImage,
    pub trailer_id: Option<String>,
    pub sort_order: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct PreviewImage {
    pub file_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub eis_listing_identifier: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub background_color: Option<String>,
    pub caption: Option<String>,
    pub file_size_in_bytes: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub foreground_color: Option<String>,
    pub height: i32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub image_position_info: Option<String>,
    pub image_purpose: String,
    #[serde(default)]
    pub unscaled_image_sha256_hash: String,
    pub uri: String,
    pub width: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct EligibilityProperties {
    pub remediations: Vec<Remediations>,
    pub affirmations: Vec<Affirmation>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Remediations {
    pub remediation_id: String,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Affirmation {
    pub affirmation_id: String,
    pub affirmation_product_id: String,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Image {
    pub file_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub eis_listing_identifier: Option<String>,
    pub background_color: String,
    pub caption: Option<String>,
    pub file_size_in_bytes: i64,
    pub foreground_color: String,
    pub height: i32,
    pub image_position_info: String,
    pub image_purpose: String,
    #[serde(default)]
    pub unscaled_image_sha256_hash: String,
    pub uri: String,
    pub width: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct SearchTitle {
    pub search_title_string: String,
    pub search_title_type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct MarketProperty {
    pub original_release_date: String,
    pub minimum_user_age: i32,
    pub content_ratings: Vec<ContentRating>,
    pub related_products: Vec<RelatedProduct>,
    pub usage_data: Vec<UsageData>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bundle_config: Option<String>,
    pub markets: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct ContentRating {
    pub rating_system: String,
    pub rating_id: String,
    pub rating_descriptors: Vec<String>,
    pub rating_disclaimers: Vec<String>,
    pub interactive_elements: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct RelatedProduct {
    pub related_product_id: String,
    pub relationship_type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct UsageData {
    pub aggregate_time_span: String,
    pub average_rating: f64,
    pub play_count: i32,
    pub rating_count: i32,
    pub rental_count: String,
    pub trial_count: String,
    pub purchase_count: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct ProductProperties {
    pub attributes: Option<Vec<Attribute>>,
    #[serde(default = "default_true")]
    pub can_install_to_sd_card: bool,
    pub category: String,
    pub categories: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subcategory: Option<String>,
    pub is_accessible: bool,
    pub is_demo: bool,
    pub is_line_of_business_app: bool,
    pub is_published_to_legacy_windows_phone_store: bool,
    pub is_published_to_legacy_windows_store: bool,
    pub package_family_name: String,
    pub package_identity_name: String,
    pub publisher_certificate_name: String,
    pub publisher_id: String,
    pub sku_display_groups: Vec<SkuDisplayGroup>,
    pub xbox_live_tier: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub xbox_xpa: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub xbox_cross_gen_set_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub xbox_console_gen_optimized: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub xbox_console_gen_compatible: Option<Vec<String>>,
    pub xbox_live_gold_required: bool,
    pub extended_metadata: Option<String>,
    #[serde(rename = "XBOX")]
    pub xbox: Option<XboxProperties>,
    pub extended_client_metadata: serde_json::Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ownership_type: Option<String>,
    pub pdp_background_color: String,
    pub has_add_ons: bool,
    pub revision_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub product_group_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub product_group_name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Attribute {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub minimum: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub maximum: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub applicable_platforms: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct SkuDisplayGroup {
    pub id: String,
    pub treatment: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct XboxProperties {
    pub xbox_properties: Option<String>,
    pub submission_id: Option<String>,
    pub xbox_gaming_metadata: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct AlternateId {
    pub id_type: String,
    pub value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct ValidationData {
    pub passed_validation: bool,
    pub revision_id: String,
    pub validation_result_uri: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProductPolicies {}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct DisplaySkuAvailability {
    pub sku: Sku,
    pub availabilities: Vec<Availability>,
    pub historical_best_availabilities: Vec<HistoricalBestAvailability>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Sku {
    pub last_modified_date: String,
    pub localized_properties: Vec<SkuLocalizedProperty>,
    pub market_properties: Vec<SkuMarketProperty>,
    pub product_id: String,
    pub properties: SkuProperties,
    pub sku_a_schema: String,
    pub sku_b_schema: String,
    pub sku_id: String,
    pub sku_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recurrence_policy: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subscription_policy_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct SkuLocalizedProperty {
    pub contributors: Vec<String>,
    pub features: Vec<String>,
    pub minimum_notes: String,
    pub recommended_notes: String,
    pub release_notes: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_platform_properties: Option<String>,
    pub sku_description: String,
    pub sku_title: String,
    pub sku_button_title: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub delivery_date_overlay: Option<String>,
    pub sku_display_rank: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text_resources: Option<String>,
    pub images: Vec<Image>,
    pub legal_text: LegalText,
    pub language: String,
    pub markets: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct LegalText {
    pub additional_license_terms: String,
    pub copyright: String,
    pub copyright_uri: String,
    pub privacy_policy: String,
    pub privacy_policy_uri: String,
    pub tou: String,
    pub tou_uri: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct SkuMarketProperty {
    pub first_available_date: String,
    pub supported_languages: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub package_ids: Option<Vec<String>>,
    #[serde(rename = "PIFilter", skip_serializing_if = "Option::is_none")]
    pub pi_filter: Option<String>,
    pub markets: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct SkuProperties {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub early_adopter_enrollment_url: Option<String>,
    pub fulfillment_data: FulfillmentData,
    pub fulfillment_type: Option<String>,
    pub fulfillment_plugin_id: Option<String>,
    #[serde(default)]
    pub has_third_party_i_a_ps: bool,
    pub last_update_date: String,
    pub hardware_properties: HardwareProperties,
    pub hardware_requirements: Vec<String>,
    pub hardware_warning_list: Vec<String>,
    pub installation_terms: String,
    pub packages: Vec<Package>,
    pub version_string: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sku_display_group_ids: Option<Vec<String>>,
    #[serde(default)]
    pub xbox_xpa: bool,
    pub bundled_skus: Vec<String>,
    pub is_repurchasable: bool,
    pub sku_display_rank: i32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_physical_store_inventory: Option<String>,
    #[serde(default)]
    pub visible_to_b2b_service_ids: Vec<String>,
    pub additional_identifiers: Vec<String>,
    pub is_trial: bool,
    pub is_pre_order: bool,
    pub is_bundle: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct FulfillmentData {
    pub product_id: String,
    pub wu_bundle_id: String,
    pub wu_category_id: String,
    pub package_family_name: String,
    pub sku_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub package_features: Option<PackageFeatures>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct PackageFeatures {
    pub supports_intelligent_delivery: bool,
    pub supports_install_features: bool,
    pub supports_install_recipes: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct HardwareProperties {
    pub minimum_hardware: Vec<String>,
    pub recommended_hardware: Vec<String>,
    pub minimum_processor: String,
    pub recommended_processor: String,
    pub minimum_graphics: String,
    pub recommended_graphics: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Package {
    pub applications: Vec<Application>,
    pub architectures: Vec<String>,
    pub capabilities: Vec<String>,
    pub device_capabilities: Vec<String>,
    pub experience_ids: Vec<String>,
    pub framework_dependencies: Vec<FrameworkDependency>,
    pub hardware_dependencies: Vec<String>,
    pub hardware_requirements: Vec<String>,
    pub hash: String,
    pub hash_algorithm: String,
    pub is_streaming_app: bool,
    pub languages: Vec<String>,
    pub max_download_size_in_bytes: i64,
    pub max_install_size_in_bytes: Option<i64>,
    pub package_format: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub package_family_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub main_package_family_name_for_dlc: Option<String>,
    pub package_full_name: String,
    pub package_id: String,
    pub content_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_id: Option<String>,
    pub package_rank: i32,
    pub package_uri: String,
    pub platform_dependencies: Vec<PlatformDependency>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub platform_dependency_xml_blob: Option<String>,
    pub resource_id: Option<String>,
    pub version: String,
    #[serde(default)]
    pub package_download_uris: Option<Vec<PackageDownloadUri>>,
    pub driver_dependencies: Vec<String>,
    pub fulfillment_data: PackageFulfillmentData,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Application {
    pub application_id: String,
    pub declaration_order: i32,
    pub extensions: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct FrameworkDependency {
    pub max_tested: i64,
    pub min_version: i64,
    pub package_identity: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct PlatformDependency {
    pub max_tested: i64,
    pub min_version: i64,
    pub platform_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct PackageDownloadUri {
    pub rank: i32,
    pub uri: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct PackageFulfillmentData {
    pub product_id: String,
    pub wu_bundle_id: String,
    pub wu_category_id: String,
    pub package_family_name: String,
    pub sku_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub package_content_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub package_features: Option<PackageFeatures>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Availability {
    pub actions: Vec<String>,
    pub availability_a_schema: String,
    pub availability_b_schema: String,
    pub availability_id: String,
    pub conditions: Conditions,
    pub last_modified_date: String,
    pub markets: Vec<String>,
    pub order_management_data: OrderManagementData,
    pub properties: serde_json::Value,
    pub sku_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub affirmation_id: Option<String>,
    pub display_rank: i32,
    #[serde(default)]
    pub remediation_required: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub licensing_data: Option<LicensingData>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Conditions {
    pub client_conditions: ClientConditions,
    pub end_date: String,
    pub resource_set_ids: Vec<String>,
    pub start_date: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub eligibility_predicate_ids: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub supported_catalog_version: Option<i32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct ClientConditions {
    pub allowed_platforms: Vec<AllowedPlatform>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct AllowedPlatform {
    pub max_version: i64,
    pub min_version: i64,
    pub platform_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct OrderManagementData {
    pub granted_entitlement_keys: Vec<String>,
    #[serde(rename = "PIFilter", skip_serializing_if = "Option::is_none")]
    pub pi_filter: Option<PIFilter>,
    pub price: Price,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct PIFilter {
    pub exclusion_properties: Vec<String>,
    pub inclusion_properties: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Price {
    pub currency_code: String,
    #[serde(default)]
    pub is_pi_required: bool,
    pub list_price: f64,
    #[serde(rename = "MSRP")]
    pub msrp: f64,
    pub tax_type: String,
    pub wholesale_currency_code: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct LicensingData {
    pub satisfying_entitlement_keys: Vec<SatisfyingEntitlementKey>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct SatisfyingEntitlementKey {
    pub entitlement_keys: Vec<String>,
    pub licensing_key_ids: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pre_order_release_date: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct HistoricalBestAvailability {
    pub actions: Vec<String>,
    pub availability_a_schema: String,
    pub availability_b_schema: String,
    pub availability_id: String,
    pub conditions: Conditions,
    pub last_modified_date: String,
    pub markets: Vec<String>,
    pub order_management_data: OrderManagementData,
    pub properties: serde_json::Value,
    pub sku_id: String,
    pub display_rank: i32,
    pub product_a_schema: String,
}
