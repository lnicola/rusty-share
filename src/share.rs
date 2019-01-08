use url::percent_encoding;

pub struct Share {
    name: String,
    link: String,
}

impl Share {
    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn link(&self) -> &str {
        &self.link
    }

    pub fn from(name: String) -> Self {
        let link =
            percent_encoding::percent_encode(name.as_bytes(), percent_encoding::DEFAULT_ENCODE_SET)
                .to_string();
        Self { name, link }
    }
}
