macro_rules! decompress {
    ( $e:expr ) => {
        match $e.decompress() {
            Some(e) => e,
            None => return Err(Error::Decompress)
        }
    }
}

macro_rules! check {
    ( $e:expr ) => {
        if $e.ct_eq(&[0; 32]).unwrap_u8() != 1 {
            $e
        } else {
            return Err(Error::Zero)
        }
    }
}
