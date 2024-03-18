pub trait Also {
    fn also(&mut self, op: impl FnOnce(&mut Self)) -> &mut Self;
}

impl<T> Also for T {
    fn also(&mut self, op: impl FnOnce(&mut Self)) -> &mut Self {
        op(self);
        self
    }
}
