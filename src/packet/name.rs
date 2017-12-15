extern crate byteorder;

use std;
use std::fmt;
use std::boxed::Box;
use std::ascii::AsciiExt;

use self::byteorder::{BigEndian, ByteOrder};
use serialize::Serializeable;

use rs_config::{ConfigAble, ConfigProvider, ParseError, self};

#[cfg(test)]
use quickcheck::Arbitrary;
#[cfg(test)]
use quickcheck::Gen;

#[derive(Clone, PartialEq, Eq, Debug, ConfigAble)]
pub struct DomainNames {
    names: Box<[DomainName]>
}

impl DomainNames {
    pub fn byte_len(&self) -> u8 {
        self.names.iter().fold(0, |r, n| r + n.byte_len())
    }
}

impl Serializeable for DomainNames {
    fn serialize_onto(&self, buffer: &mut Vec<u8>) {
        for name in self.names.iter() {
            name.push_to(buffer);
        }
    }

    fn deserialize_from(buffer: &[u8]) -> Result<Self, String> {
        let mut offset = 0;
        let mut vec = Vec::new();
        while offset < buffer.len() {
            let (mut name, i) = Name::scan(offset, buffer)?;
            vec.push(DomainName::from_name(&mut name));
            offset = i;
        }

        Ok(DomainNames{names: vec.into_boxed_slice()})
    }
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct DomainName {
    /// We are going with the ascii limitation of hostnames.
    /// In theory DNS is just bit octets, but this makes things more bearable for us.
    labels: Box<[Box<[u8]>]>,
}

impl ConfigAble for DomainName {
    fn get_format<F>(_: &mut std::collections::HashSet<String>, fun: &mut F)
        where F: FnMut(&str) {
        fun("a.b.c.")
    }

    fn get_name() -> &'static str { "DomainName" }

    fn parse_from<F>(provider: &mut ConfigProvider, fun: &mut F) -> Result<Self, ParseError>
        where F: FnMut(String) {
        if let Some(txt) = provider.get_next() {
            let using: String = txt.chars().filter(|c| c.is_alphanumeric() || *c == '.' || *c == '_').collect();


            if using.len() > 253 {
                fun(format!("Domain name \"{}\" would be longer than allowed by the DNS specification", using));
                provider.consume(using.len(), fun)?;
                return Err(ParseError::Recoverable);
            }

            let labels: Vec<&str> = using.split('.').collect();

            if labels.iter().any(|l| l.len() > 63) {
                fun(format!("Domain name \"{}\" contains a label longer than 63 chars", using));
                provider.consume(using.len(), fun)?;
                return Err(ParseError::Recoverable);
            }

            let tmp: Vec<Box<[u8]>> = labels.iter().map(|l| {
                    let t: Vec<u8> = l.as_bytes().iter().map(|b| *b).collect();
                    t.into_boxed_slice()
                }).collect();

            provider.consume(using.len(), fun)?;
            return Ok(DomainName{ labels: tmp.into_boxed_slice() });
        }

        Err(ParseError::Final)
    }

    fn get_default() -> Result<Self, ()> {Err(()) }

}

impl fmt::Display for DomainName {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        for label in self.labels.iter() {
            String::from_utf8_lossy(label).fmt(fmt)?;
            '.'.fmt(fmt)?;
        }

        Ok(())
    }
}

impl DomainName {
    // Pushes a *single* domain name to a buffer
    fn push_to(&self, buffer: &mut Vec<u8>) {
        for label in self.labels.iter() {
            buffer.push(label.len() as u8);
            buffer.extend(label.iter());
        }

        buffer.push(0);
    }

    fn from_name(name: &mut Name) -> Self {
        let v: Vec<Box<[u8]>> = name.map(|l| {
            let lv: Vec<u8> = l.iter().map(|b| *b).collect();
            lv.into_boxed_slice()
        }).collect();

        DomainName { labels: v.into_boxed_slice() }
    }

    fn byte_len(&self) -> u8 {
        let format = self.labels.len() as u8 + 1;
        self.labels.iter().fold(format, |i, l| i + l.len() as u8)
    }
}


/// The DNS name as stored in the original packet
///
/// This is contains just a reference to a slice that contains the data.
/// You may turn this into a string using `.to_string()`
#[derive(Debug, Clone, Copy)]
pub struct Name<'a>{
    /// This is the original buffer size. The compressed names in original
    /// are calculated in this buffer
    labels: &'a [u8],

    /// Used in the iterator implementation to store the offset of the currently parsed element
    current: usize,
}

impl<'a> Name<'a> {
    pub fn scan(offset: usize, data: &'a[u8]) -> Result<(Name<'a>, usize), String> {
        let mut pos = offset;
        loop {
            if data.len() <= pos {
                return Err(String::from("Tried to read dns label behind data buffer"));
            }
            let byte = data[pos];
            if byte == 0 {
                return Ok((Name {labels: data, current: offset}, pos + 1));
            } else if byte & 0b1100_0000 == 0b1100_0000 {
                // Parsing a pointer into the data
                if data.len() < pos+2 {
                    return Err(String::from("Encountered DNS pointer but no byte left in buffer"));
                }

                let off = (BigEndian::read_u16(&data[pos..pos+2])
                           & !0b1100_0000_0000_0000) as usize;

                if off >= data.len() {
                    return Err(String::from("Encountered DNS label offset behind data buffer"));
                }

                // Validate referred to location
                Name::scan(off as usize, data)?;

                return Ok((Name {labels: data, current: offset}, pos + 2));
            } else if byte & 0b1100_0000 == 0 {
                let end = pos + byte as usize + 1;

                if data.len() <= end {
                    return Err(String::from("Encountered label longer than data left in buffer"));
                }

                if !data[pos+1..end].is_ascii() {
                    return Err(String::from("Encountered non-ascii character in DNS label."));
                }

                pos = end;
                continue;
            } else {
                return Err(format!("Encountered illegal length value for DNS label: {:x}", byte));
            }
        }
    }
}

impl<'a> Iterator for Name<'a> {
    type Item=&'a [u8];

    fn next(&mut self) -> Option<Self::Item> {
        let size = self.labels[self.current] as usize;
        if size == 0 {
            return None;
        }

        if size & 0xC0 == 0xC0 {
            let off = (BigEndian::read_u16(&self.labels[self.current..self.current+2])
                       & !0b1100_0000_0000_0000) as usize;
            self.current = off as usize;
            return self.next();
        }

        let ret = &self.labels[self.current + 1 .. self.current + 1 + size];
        self.current = self.current + size + 1;

        return Some(ret);
    }
}

#[cfg(test)]
impl Arbitrary for DomainName {
    fn arbitrary<G: Gen>(gen: &mut G) -> Self {
        let g: Vec<Vec<u8>> = Arbitrary::arbitrary(gen);
        let r: Vec<Vec<u8>> = g.into_iter()
                .map(|l| l
                     .into_iter()
                     .filter(|b| b.is_ascii()).take(63).collect())
                .filter(|l: &Vec<u8>| !l.is_empty()).collect();

        let t: Vec<Box<[u8]>> = r.into_iter().map(|l| l.into_boxed_slice()).collect();


        DomainName {
            labels: t.into_boxed_slice()
        }
    }
}

#[cfg(test)]
impl Arbitrary for DomainNames {
    fn arbitrary<G: Gen>(gen: &mut G) -> Self {
        let t: Vec<DomainName> = Arbitrary::arbitrary(gen);
        DomainNames {
            names: t.into_boxed_slice()
        }
    }
}

#[cfg(test)]
mod tests {
    use packet::name::{DomainNames, DomainName, Name};
    use serialize;

    use std::ops::Deref;

    quickcheck! {
        fn serialize_domain_name(name: DomainName) -> bool {
            let mut buffer = Vec::new();
            name.push_to(&mut buffer);
            let scanned = Name::scan(0, buffer.as_slice());

            if let Ok(mut n) = scanned {
                return DomainName::from_name(&mut n.0) == name;
            }

            return false;
        }

        fn serialize_domain_names(names: DomainNames) -> bool {
            let buffer = serialize::serialize(&names);
            let cmp = serialize::deserialize(buffer.deref());

            cmp == Ok(names)
        }
    }
}
