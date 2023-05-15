use crate::Supabase;

impl Supabase {
    pub fn fetch(&self) -> &postgrest::Postgrest {
        &self.db
    }
}
