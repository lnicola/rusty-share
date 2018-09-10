use http::Request;
use tower_web::extract::{Context, Extract, Immediate};
use tower_web::util::BufStream;

pub struct RequestWrapper(Request<()>);

impl RequestWrapper {
    pub fn into(self) -> Request<()> {
        self.0
    }
}

impl<B: BufStream> Extract<B> for RequestWrapper {
    type Future = Immediate<Self>;

    fn extract(ctx: &Context) -> Self::Future {
        let mut request = Request::builder()
            .method(ctx.request().method())
            .version(ctx.request().version())
            .uri(ctx.request().uri())
            .body(())
            .unwrap();
        request
            .headers_mut()
            .extend(ctx.request().headers().clone());
        Immediate::ok(RequestWrapper(request))
    }
}
