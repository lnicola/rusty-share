use std::path::{Component, Path};

pub trait PathExt {
    fn is_root(&self) -> bool;
}

impl PathExt for Path {
    fn is_root(&self) -> bool {
        let mut components = self.components();
        components.next() == Some(Component::RootDir) && components.next() == None
    }
}
