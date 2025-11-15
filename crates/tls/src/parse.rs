use anyhow::Result;

pub trait Parse: Sized {
    fn parse(raw: &[u8]) -> Result<Self>;

    fn size(&self) -> usize;
}

impl Parse for u8 {
    fn parse(raw: &[u8]) -> Result<Self> {
        Ok(raw[0])
    }

    fn size(&self) -> usize {
        1
    }
}

impl Parse for u16 {
    fn parse(raw: &[u8]) -> Result<Self> {
        Ok(u16::from_be_bytes([raw[0], raw[1]]))
    }

    fn size(&self) -> usize {
        2
    }
}

#[derive(Debug)]
pub struct DataVec8<T>
where
    T: Parse,
{
    pub length: u8,
    pub data: Box<[T]>,
}

impl<T> Parse for DataVec8<T>
where
    T: Parse,
{
    fn parse(raw: &[u8]) -> Result<Self> {
        let length = raw[0];
        let payload = &raw[1..];

        let mut res = Vec::new();
        let mut offset: usize = 0;
        while offset < length as usize {
            let el = T::parse(&payload[offset..])?;
            offset += el.size();
            res.push(el);
        }

        Ok(Self {
            length,
            data: res.into_boxed_slice(),
        })
    }

    fn size(&self) -> usize {
        self.length as usize + 1
    }
}

impl<T> DataVec8<T>
where
    T: Parse,
{
    pub fn into_inner(self) -> Box<[T]> {
        self.data
    }
}

#[derive(Debug)]
pub struct DataVec16<T>
where
    T: Parse,
{
    length: u16,
    data: Box<[T]>,
}

impl<T> Parse for DataVec16<T>
where
    T: Parse,
{
    fn parse(raw: &[u8]) -> Result<Self> {
        let length = u16::from_be_bytes([raw[0], raw[1]]);
        let payload = &raw[2..];

        let mut res = Vec::new();
        let mut offset: usize = 0;
        while offset < length as usize {
            let el = T::parse(&payload[offset..])?;
            offset += el.size();
            res.push(el);
        }

        Ok(Self {
            length,
            data: res.into_boxed_slice(),
        })
    }

    fn size(&self) -> usize {
        self.length as usize + 2
    }
}

impl<T> DataVec16<T>
where
    T: Parse,
{
    pub fn into_inner(self) -> Box<[T]> {
        self.data
    }
}
