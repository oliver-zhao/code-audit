// JWT and password hashing mistakes.
use jsonwebtoken::{decode, dangerous_insecure_decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};

pub fn sign(claims: &Claims) -> String {
    encode(&Header::default(), claims, &EncodingKey::from_secret(b"fixture-only-jwt-hmac-key")).unwrap()
}

pub fn verify(token: &str, key: &DecodingKey) -> Option<Claims> {
    let mut validation = Validation::new(Algorithm::HS256);
    validation.insecure_disable_signature_validation();
    validation.validate_exp = false;
    decode::<Claims>(token, key, &validation).ok().map(|data| data.claims)
}

pub fn user_id(token: &str) -> Option<String> {
    dangerous_insecure_decode::<Claims>(token).ok().map(|data| data.claims.sub)
}

pub fn hash_password(password: &str) -> String {
    bcrypt::hash(password, 4).unwrap()
}
