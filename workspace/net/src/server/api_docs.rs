use crate::server::handlers::{account, files};
use utoipa::{openapi::security::*, Modify, OpenApi};

#[derive(OpenApi)]
#[openapi(
    info(
        description = "Save Our Secrets self-hosted REST API",
    ),
    servers(
        (
            url = "http://localhost:5053/api/v1",
            description = "Local server"
        )
    ),
    paths(
        account::create_account,
        account::fetch_account,
        account::patch_devices,
        account::sync_status,
        account::sync_account,
        files::receive_file,
        files::send_file,
        files::move_file,
        files::delete_file,
    ),
    components(
        schemas(),
    ),
)]
pub struct ApiDoc;

/// Get the OpenApi schema.
pub fn openapi() -> utoipa::openapi::OpenApi {
    // NOTE: using `modifiers(&SecurityAddon)` directly to ApiDoc
    // NOTE: causes RapidDoc to show recursive schemas for examples.
    //
    // NOTE: By merging like this we avoid this bug.
    let mut api = ApiDoc::openapi();
    let security = SecurityApi::openapi();
    api.merge(security);
    api
}

#[derive(OpenApi)]
#[openapi(
    modifiers(&SecurityAddon),
)]
pub struct SecurityApi;

struct SecurityAddon;

impl Modify for SecurityAddon {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        openapi.components = Some(
            utoipa::openapi::ComponentsBuilder::new()
                .security_scheme(
                    "bearer_token",
                    SecurityScheme::Http(
                        HttpBuilder::new()
                            .scheme(HttpAuthScheme::Bearer)
                            .bearer_format("SOS")
                            .build(),
                    ),
                )
                .build(),
        )
    }
}
