use crate::Supabase;

impl Supabase {
    pub fn db(&self) -> &postgrest::Postgrest {
        &self.db
    }
}
