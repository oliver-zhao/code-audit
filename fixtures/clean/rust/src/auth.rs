// JWT validated with a key from the environment; bcrypt with the default cost.
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};

pub fn sign(claims: &Claims, secret: &[u8]) -> String {
    encode(&Header::default(), claims, &EncodingKey::from_secret(secret)).unwrap()
}

pub fn verify(token: &str, key: &DecodingKey) -> Option<Claims> {
    let mut validation = Validation::new(Algorithm::HS256);
    validation.validate_exp = true;
    decode::<Claims>(token, key, &validation).ok().map(|data| data.claims)
}

pub fn hash_password(password: &str) -> String {
    bcrypt::hash(password, bcrypt::DEFAULT_COST).unwrap()
}

pub fn hash_password_strong(password: &str) -> String {
    bcrypt::hash(password, 12).unwrap()
}
