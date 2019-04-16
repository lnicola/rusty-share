use url::percent_encoding;

#[derive(Debug)]
pub struct Share {
    name: String,
    link: String,
}

impl Share {
    pub fn new(name: String) -> Self {
        let link =
            percent_encoding::percent_encode(name.as_bytes(), percent_encoding::DEFAULT_ENCODE_SET)
                .to_string();
        Self { name, link }
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn link(&self) -> &str {
        &self.link
    }
}