mod fast {
    const PARAMETERS: transparent_pq_keys::ParameterSet =
        transparent_pq_keys::ParameterSet::Sha2_128f;
    include!("cases/lifecycle.rs");
}
mod small {
    const PARAMETERS: transparent_pq_keys::ParameterSet =
        transparent_pq_keys::ParameterSet::Sha2_192s;
    include!("cases/lifecycle.rs");
}
