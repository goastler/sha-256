#![no_std]

use core::iter::Iterator;
use core::convert::TryInto;

/// A structure representing the SHA-256 hash algorithm.
pub struct Sha256 {
    w: [u32; 64], // words for the message schedule
    // the 8 hash values
    h0: u32,
    h1: u32,
    h2: u32,
    h3: u32,
    h4: u32,
    h5: u32,
    h6: u32,
    h7: u32,
    // number of 64 byte chunks in the message
    n_chunks: usize,
}

impl Sha256 {

    /// Creates a new instance of the SHA-256 hash algorithm.
    ///
    /// # Returns
    /// A new `Sha256` instance with initialized state.
    pub fn new() -> Self {
        Self {
            w: [0; 64],
            h0: 0,
            h1: 0,
            h2: 0,
            h3: 0,
            h4: 0,
            h5: 0,
            h6: 0,
            h7: 0,
            n_chunks: 0,
        }
    }

    /// Sets the last chunk of the message for SHA-256 processing.
    ///
    /// # Arguments
    /// * `msg` - A byte slice representing the message to be hashed.
    #[inline(always)]
    fn set_chunk_last(&mut self, msg: &[u8]) {
        unsafe {
            let index = self.n_chunks - 1;
            let msg_len = msg.len();

            let start = index * 64;
            // take the bytes of the message in 4 byte chunks
            let n_u32s = (msg_len - start) / 4;
            let end = start + n_u32s * 4;
            // copy each set of 4 bytes into the w array
            for (i, chunk) in msg[start..end].chunks_exact(4).enumerate() {
                self.w[i] = u32::from_be_bytes(chunk.try_into().unwrap());
            }

            let mut msg_last_u32_bytes = [0u8; 4];
            let rem_bytes = msg_len % 4;
            let rem_bytes_start = msg_len - rem_bytes;
            // copy the rest of the message (which will be 0-3 bytes) into the bytes array for the last u32
            msg_last_u32_bytes[..rem_bytes].copy_from_slice(&msg[rem_bytes_start..msg_len]);
            // the next byte after the message is 0b10000000
            msg_last_u32_bytes[rem_bytes] = 0b10000000;
            // the rest of the bytes in the last u32 is 0, which the array was init'd to.
            // copy the last u32 into the w array
            self.w[n_u32s] = u32::from_be_bytes(msg_last_u32_bytes);

            // the remaining u32's of the last chunk are 0
            // the last 2 u32's are the length of the message, already been set
            for i in n_u32s + 1..14 {
                self.w[i] = 0;
            }

            // the message length (in bits!) as a u64 in big endian needs to go at the end in the last 2 u32's
            let len = (msg_len * 8) as u64;
            let len_upper_bytes = ((len >> 32) as u32).to_be_bytes();
            let len_lower_bytes = ((len & 0xFFFFFFFF) as u32).to_be_bytes();
            self.w[14] = u32::from_be_bytes(len_upper_bytes);
            self.w[15] = u32::from_be_bytes(len_lower_bytes);
        }
    }

    /// Sets a chunk of the message for SHA-256 processing.
    ///
    /// # Arguments
    /// * `msg` - A byte slice representing the message to be hashed.
    /// * `index` - The index of the chunk to be set.
    #[inline(always)]
    fn set_chunk(&mut self, msg: &[u8], index: usize) {
        unsafe {
            let start = index * 64;
            let end = start + 64;
            let slice = &msg[start..end];
            for (i, chunk) in slice.chunks_exact(4).enumerate() {
                self.w[i] = u32::from_be_bytes(chunk.try_into().unwrap());
            }
        }
    }

    /// Sets the number of chunks for the given message.
    ///
    /// # Arguments
    /// * `msg` - A byte slice representing the message to be hashed.
    #[inline(always)]
    fn set_n_chunks(&mut self, msg: &[u8]) {
        let msg_len = msg.len();
        let padding_bytes = 64 - ((msg_len + 1 + 8) % 64);
        let total_length = msg_len + 1 + padding_bytes + 8;
        self.n_chunks = total_length / 64;
    }

    /// Processes a single chunk of the message using the SHA-256 algorithm.
    #[inline(always)]
    fn sha256_chunk(&mut self) {
        unsafe {
            // Extend w to 64 words
            // partially unrolled loop, 8 iterations at a time
            // why 8? gets a reasonable amount of variable reuse through the indexing of the w array, but doesn't unroll the loop too a point where the code size is too large for the gains
            for i in (16..64).step_by(8) {
                // could reuse repeats of variables, but we don't because benchmarks show it's slower. I _think_ it's something to do with cache hits for array elements being faster than reusing variables

                // First iteration: i
                let w15_0 = self.w[i - 15];
                let s0_0 = w15_0.rotate_right(7) ^ w15_0.rotate_right(18) ^ (w15_0 >> 3);
                let w2_0 = self.w[i - 2];
                let s1_0 = w2_0.rotate_right(17) ^ w2_0.rotate_right(19) ^ (w2_0 >> 10);
                self.w[i] = self.w[i - 16]
                    .wrapping_add(s0_0)
                    .wrapping_add(self.w[i - 7])
                    .wrapping_add(s1_0);

                // Second iteration: i + 1
                let w15_1 = self.w[i - 14];
                let s0_1 = w15_1.rotate_right(7) ^ w15_1.rotate_right(18) ^ (w15_1 >> 3);
                let w2_1 = self.w[i - 1];
                let s1_1 = w2_1.rotate_right(17) ^ w2_1.rotate_right(19) ^ (w2_1 >> 10);
                self.w[i + 1] = self.w[i - 15]
                    .wrapping_add(s0_1)
                    .wrapping_add(self.w[i - 6])
                    .wrapping_add(s1_1);

                // Third iteration: i + 2
                let w15_2 = self.w[i - 13];
                let s0_2 = w15_2.rotate_right(7) ^ w15_2.rotate_right(18) ^ (w15_2 >> 3);
                let w2_2 = self.w[i];
                let s1_2 = w2_2.rotate_right(17) ^ w2_2.rotate_right(19) ^ (w2_2 >> 10);
                self.w[i + 2] = self.w[i - 14]
                    .wrapping_add(s0_2)
                    .wrapping_add(self.w[i - 5])
                    .wrapping_add(s1_2);

                // Fourth iteration: i + 3
                let w15_3 = self.w[i - 12];
                let s0_3 = w15_3.rotate_right(7) ^ w15_3.rotate_right(18) ^ (w15_3 >> 3);
                let w2_3 = self.w[i + 1];
                let s1_3 = w2_3.rotate_right(17) ^ w2_3.rotate_right(19) ^ (w2_3 >> 10);
                self.w[i + 3] = self.w[i - 13]
                    .wrapping_add(s0_3)
                    .wrapping_add(self.w[i - 4])
                    .wrapping_add(s1_3);

                // Fifth iteration: i + 4
                let w15_4 = self.w[i - 11];
                let s0_4 = w15_4.rotate_right(7) ^ w15_4.rotate_right(18) ^ (w15_4 >> 3);
                let w2_4 = self.w[i + 2];
                let s1_4 = w2_4.rotate_right(17) ^ w2_4.rotate_right(19) ^ (w2_4 >> 10);
                self.w[i + 4] = self.w[i - 12]
                    .wrapping_add(s0_4)
                    .wrapping_add(self.w[i - 3])
                    .wrapping_add(s1_4);

                // Sixth iteration: i + 5
                let w15_5 = self.w[i - 10];
                let s0_5 = w15_5.rotate_right(7) ^ w15_5.rotate_right(18) ^ (w15_5 >> 3);
                let w2_5 = self.w[i + 3];
                let s1_5 = w2_5.rotate_right(17) ^ w2_5.rotate_right(19) ^ (w2_5 >> 10);
                self.w[i + 5] = self.w[i - 11]
                    .wrapping_add(s0_5)
                    .wrapping_add(self.w[i - 2])
                    .wrapping_add(s1_5);

                // Seventh iteration: i + 6
                let w15_6 = self.w[i - 9];
                let s0_6 = w15_6.rotate_right(7) ^ w15_6.rotate_right(18) ^ (w15_6 >> 3);
                let w2_6 = self.w[i + 4];
                let s1_6 = w2_6.rotate_right(17) ^ w2_6.rotate_right(19) ^ (w2_6 >> 10);
                self.w[i + 6] = self.w[i - 10]
                    .wrapping_add(s0_6)
                    .wrapping_add(self.w[i - 1])
                    .wrapping_add(s1_6);

                // Eighth iteration: i + 7
                let w15_7 = self.w[i - 8];
                let s0_7 = w15_7.rotate_right(7) ^ w15_7.rotate_right(18) ^ (w15_7 >> 3);
                let w2_7 = self.w[i + 5];
                let s1_7 = w2_7.rotate_right(17) ^ w2_7.rotate_right(19) ^ (w2_7 >> 10);
                self.w[i + 7] = self.w[i - 9]
                    .wrapping_add(s0_7)
                    .wrapping_add(self.w[i])
                    .wrapping_add(s1_7);
            }

            let mut a = self.h0;
            let mut b = self.h1;
            let mut c = self.h2;
            let mut d = self.h3;
            let mut e = self.h4;
            let mut f = self.h5;
            let mut g = self.h6;
            let mut h = self.h7;

            // partially unrolled loop, 8 iterations at a time
            for i in (0..64).step_by(8) {
                // First iteration: i
                let s1_0 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
                let ch_0 = (e & f) ^ ((!e) & g);
                let temp1_0 = h
                    .wrapping_add(s1_0)
                    .wrapping_add(ch_0)
                    .wrapping_add(K[i])
                    .wrapping_add(self.w[i]);
                let s0_0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
                let maj_0 = (a & b) ^ (a & c) ^ (b & c);
                let temp2_0 = s0_0.wrapping_add(maj_0);

                h = g;
                g = f;
                f = e;
                e = d.wrapping_add(temp1_0);
                d = c;
                c = b;
                b = a;
                a = temp1_0.wrapping_add(temp2_0);

                // Second iteration: i + 1
                let s1_1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
                let ch_1 = (e & f) ^ ((!e) & g);
                let temp1_1 = h
                    .wrapping_add(s1_1)
                    .wrapping_add(ch_1)
                    .wrapping_add(K[i + 1])
                    .wrapping_add(self.w[i + 1]);
                let s0_1 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
                let maj_1 = (a & b) ^ (a & c) ^ (b & c);
                let temp2_1 = s0_1.wrapping_add(maj_1);

                h = g;
                g = f;
                f = e;
                e = d.wrapping_add(temp1_1);
                d = c;
                c = b;
                b = a;
                a = temp1_1.wrapping_add(temp2_1);

                // Third iteration: i + 2
                let s1_2 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
                let ch_2 = (e & f) ^ ((!e) & g);
                let temp1_2 = h
                    .wrapping_add(s1_2)
                    .wrapping_add(ch_2)
                    .wrapping_add(K[i + 2])
                    .wrapping_add(self.w[i + 2]);
                let s0_2 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
                let maj_2 = (a & b) ^ (a & c) ^ (b & c);
                let temp2_2 = s0_2.wrapping_add(maj_2);

                h = g;
                g = f;
                f = e;
                e = d.wrapping_add(temp1_2);
                d = c;
                c = b;
                b = a;
                a = temp1_2.wrapping_add(temp2_2);

                // Fourth iteration: i + 3
                let s1_3 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
                let ch_3 = (e & f) ^ ((!e) & g);
                let temp1_3 = h
                    .wrapping_add(s1_3)
                    .wrapping_add(ch_3)
                    .wrapping_add(K[i + 3])
                    .wrapping_add(self.w[i + 3]);
                let s0_3 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
                let maj_3 = (a & b) ^ (a & c) ^ (b & c);
                let temp2_3 = s0_3.wrapping_add(maj_3);

                h = g;
                g = f;
                f = e;
                e = d.wrapping_add(temp1_3);
                d = c;
                c = b;
                b = a;
                a = temp1_3.wrapping_add(temp2_3);

                // Fifth iteration: i + 4
                let s1_4 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
                let ch_4 = (e & f) ^ ((!e) & g);
                let temp1_4 = h
                    .wrapping_add(s1_4)
                    .wrapping_add(ch_4)
                    .wrapping_add(K[i + 4])
                    .wrapping_add(self.w[i + 4]);
                let s0_4 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
                let maj_4 = (a & b) ^ (a & c) ^ (b & c);
                let temp2_4 = s0_4.wrapping_add(maj_4);

                h = g;
                g = f;
                f = e;
                e = d.wrapping_add(temp1_4);
                d = c;
                c = b;
                b = a;
                a = temp1_4.wrapping_add(temp2_4);

                // Sixth iteration: i + 5
                let s1_5 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
                let ch_5 = (e & f) ^ ((!e) & g);
                let temp1_5 = h
                    .wrapping_add(s1_5)
                    .wrapping_add(ch_5)
                    .wrapping_add(K[i + 5])
                    .wrapping_add(self.w[i + 5]);
                let s0_5 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
                let maj_5 = (a & b) ^ (a & c) ^ (b & c);
                let temp2_5 = s0_5.wrapping_add(maj_5);

                h = g;
                g = f;
                f = e;
                e = d.wrapping_add(temp1_5);
                d = c;
                c = b;
                b = a;
                a = temp1_5.wrapping_add(temp2_5);

                // Seventh iteration: i + 6
                let s1_6 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
                let ch_6 = (e & f) ^ ((!e) & g);
                let temp1_6 = h
                    .wrapping_add(s1_6)
                    .wrapping_add(ch_6)
                    .wrapping_add(K[i + 6])
                    .wrapping_add(self.w[i + 6]);
                let s0_6 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
                let maj_6 = (a & b) ^ (a & c) ^ (b & c);
                let temp2_6 = s0_6.wrapping_add(maj_6);

                h = g;
                g = f;
                f = e;
                e = d.wrapping_add(temp1_6);
                d = c;
                c = b;
                b = a;
                a = temp1_6.wrapping_add(temp2_6);

                // Eighth iteration: i + 7
                let s1_7 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
                let ch_7 = (e & f) ^ ((!e) & g);
                let temp1_7 = h
                    .wrapping_add(s1_7)
                    .wrapping_add(ch_7)
                    .wrapping_add(K[i + 7])
                    .wrapping_add(self.w[i + 7]);
                let s0_7 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
                let maj_7 = (a & b) ^ (a & c) ^ (b & c);
                let temp2_7 = s0_7.wrapping_add(maj_7);

                h = g;
                g = f;
                f = e;
                e = d.wrapping_add(temp1_7);
                d = c;
                c = b;
                b = a;
                a = temp1_7.wrapping_add(temp2_7);
            }

            self.h0 = self.h0.wrapping_add(a);
            self.h1 = self.h1.wrapping_add(b);
            self.h2 = self.h2.wrapping_add(c);
            self.h3 = self.h3.wrapping_add(d);
            self.h4 = self.h4.wrapping_add(e);
            self.h5 = self.h5.wrapping_add(f);
            self.h6 = self.h6.wrapping_add(g);
            self.h7 = self.h7.wrapping_add(h);
        }
    }

    /// Computes the SHA-256 digest of the given message.
    ///
    /// # Arguments
    /// * `msg` - A byte slice representing the message to be hashed.
    ///
    /// # Returns
    /// A 32-byte array representing the SHA-256 hash of the message.
    pub fn digest(&mut self, msg: &[u8]) -> [u8; 32] {
        self.h0 = 0x6a09e667;
        self.h1 = 0xbb67ae85;
        self.h2 = 0x3c6ef372;
        self.h3 = 0xa54ff53a;
        self.h4 = 0x510e527f;
        self.h5 = 0x9b05688c;
        self.h6 = 0x1f83d9ab;
        self.h7 = 0x5be0cd19;

        self.set_n_chunks(msg);
        for i in 0..self.n_chunks - 1 {
            self.set_chunk(msg, i);
            self.sha256_chunk();
        }
        self.set_chunk_last(msg);
        self.sha256_chunk();

        // Create the output hash
        let mut hash = [0; 32];
        unsafe {
            hash[0..4].copy_from_slice(&self.h0.to_be_bytes());
            hash[4..8].copy_from_slice(&self.h1.to_be_bytes());
            hash[8..12].copy_from_slice(&self.h2.to_be_bytes());
            hash[12..16].copy_from_slice(&self.h3.to_be_bytes());
            hash[16..20].copy_from_slice(&self.h4.to_be_bytes());
            hash[20..24].copy_from_slice(&self.h5.to_be_bytes());
            hash[24..28].copy_from_slice(&self.h6.to_be_bytes());
            hash[28..32].copy_from_slice(&self.h7.to_be_bytes());
        }

        hash
    }
}

const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];
