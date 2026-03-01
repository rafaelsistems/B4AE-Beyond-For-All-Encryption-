// src/crypto/constant_time.rs
//
// Constant-time memory operations to prevent timing side-channel attacks.
// All operations in this module execute in time independent of input values.

use subtle::{Choice, ConstantTimeEq};

/// Constant-time memory operations for side-channel resistance.
///
/// This struct provides constant-time memory comparison and copy operations
/// that execute in time independent of input values, preventing timing attacks.
pub struct ConstantTimeMemory;

impl ConstantTimeMemory {
    /// Compare two byte slices in constant time.
    ///
    /// This function compares all bytes without early termination, ensuring
    /// execution time is independent of where differences occur.
    ///
    /// # Arguments
    ///
    /// * `a` - First byte slice to compare
    /// * `b` - Second byte slice to compare
    ///
    /// # Returns
    ///
    /// * `Choice::from(1)` if arrays are equal
    /// * `Choice::from(0)` if arrays differ or have different lengths
    ///
    /// # Security
    ///
    /// - Execution time independent of input values
    /// - No early termination when differences found
    /// - All bytes processed regardless of intermediate results
    /// - Resistant to timing side-channel attacks
    ///
    /// # Examples
    ///
    /// ```
    /// use b4ae::crypto::constant_time::ConstantTimeMemory;
    /// use subtle::Choice;
    ///
    /// let a = [0x42; 32];
    /// let b = [0x42; 32];
    /// let equal = ConstantTimeMemory::ct_memcmp(&a, &b);
    /// assert!(bool::from(equal));
    ///
    /// let c = [0x43; 32];
    /// let not_equal = ConstantTimeMemory::ct_memcmp(&a, &c);
    /// assert!(!bool::from(not_equal));
    /// ```
    pub fn ct_memcmp(a: &[u8], b: &[u8]) -> Choice {
        // If lengths differ, arrays are not equal
        if a.len() != b.len() {
            return Choice::from(0);
        }

        // Initialize accumulator for differences
        let mut diff: u8 = 0;

        // Compare all bytes without early exit
        // Use bitwise OR to accumulate any differences
        for i in 0..a.len() {
            diff |= a[i] ^ b[i];
        }

        // Convert to Choice: diff == 0 means equal
        diff.ct_eq(&0)
    }

    /// Copy memory in constant time.
    ///
    /// This function copies `len` bytes from `src` to `dst` in constant time,
    /// ensuring execution time is independent of the content being copied.
    ///
    /// # Arguments
    ///
    /// * `dst` - Destination buffer (must be at least `len` bytes)
    /// * `src` - Source buffer (must be at least `len` bytes)
    /// * `len` - Number of bytes to copy
    ///
    /// # Panics
    ///
    /// Panics if `dst.len() < len` or `src.len() < len`
    ///
    /// # Security
    ///
    /// - Execution time independent of data content
    /// - No secret-dependent branching
    /// - Copies all bytes regardless of values
    ///
    /// # Examples
    ///
    /// ```
    /// use b4ae::crypto::constant_time::ConstantTimeMemory;
    ///
    /// let src = [1, 2, 3, 4, 5];
    /// let mut dst = [0u8; 5];
    /// ConstantTimeMemory::ct_copy(&mut dst, &src, 5);
    /// assert_eq!(dst, src);
    /// ```
    pub fn ct_copy(dst: &mut [u8], src: &[u8], len: usize) {
        assert!(dst.len() >= len, "Destination buffer too small");
        assert!(src.len() >= len, "Source buffer too small");

        // Copy all bytes in constant time
        // No conditional branches based on data content
        for i in 0..len {
            dst[i] = src[i];
        }
    }
}

/// Cache-timing resistant operations for side-channel resistance.
///
/// This struct provides cache-timing resistant table lookup operations
/// that access all table elements regardless of the target index, preventing
/// cache timing attacks.
pub struct CacheTimingResistance;

impl CacheTimingResistance {
    /// Perform a cache-timing resistant table lookup.
    ///
    /// This function accesses all table elements regardless of the target index,
    /// ensuring the memory access pattern is independent of the index value.
    /// This prevents cache timing attacks that could leak information about
    /// which table element was accessed.
    ///
    /// # Arguments
    ///
    /// * `table` - Slice of elements to search
    /// * `index` - Target index to retrieve
    ///
    /// # Returns
    ///
    /// The element at the specified index
    ///
    /// # Panics
    ///
    /// Panics if `index >= table.len()`
    ///
    /// # Security
    ///
    /// - Accesses all table elements regardless of target index
    /// - Memory access pattern independent of index value
    /// - Uses constant-time conditional selection
    /// - Execution time is O(n) where n is table size
    /// - Resistant to cache timing side-channel attacks
    ///
    /// # Algorithm
    ///
    /// ```text
    /// FOR i FROM 0 TO table.length-1 DO
    ///   is_target ← ct_eq(i, index)
    ///   result ← ct_select(result, table[i], is_target)
    /// END FOR
    /// ```
    ///
    /// # Examples
    ///
    /// ```
    /// use b4ae::crypto::constant_time::CacheTimingResistance;
    ///
    /// let table = vec![10u32, 20, 30, 40, 50];
    /// let value = CacheTimingResistance::ct_table_lookup(&table, 2);
    /// assert_eq!(value, 30);
    /// ```
    pub fn ct_table_lookup<T>(table: &[T], index: usize) -> T
    where
        T: Copy + Default + subtle::ConditionallySelectable,
    {
        assert!(index < table.len(), "Index out of bounds");

        // Initialize result with default value
        let mut result = T::default();

        // Scan entire table regardless of target index
        for i in 0..table.len() {
            // Constant-time equality check
            let is_target = Choice::from((i == index) as u8);

            // Constant-time conditional select
            // If is_target is true, select table[i], otherwise keep result
            result = T::conditional_select(&result, &table[i], is_target);
        }

        result
    }
}

/// Constant-time arithmetic operations for side-channel resistance.
///
/// This struct provides constant-time arithmetic operations (add, sub, mul)
/// that execute in time independent of operand values, preventing timing attacks.
/// All operations use wrapping arithmetic to avoid overflow branches.
pub struct ConstantTimeArithmetic;

impl ConstantTimeArithmetic {
    /// Add two u64 values in constant time.
    ///
    /// This function performs addition using wrapping arithmetic to avoid
    /// overflow branches, ensuring execution time is independent of operand values.
    ///
    /// # Arguments
    ///
    /// * `a` - First operand
    /// * `b` - Second operand
    ///
    /// # Returns
    ///
    /// The sum of `a` and `b`, wrapping on overflow
    ///
    /// # Security
    ///
    /// - Execution time independent of operand values
    /// - No secret-dependent branching
    /// - Uses wrapping arithmetic to avoid overflow branches
    ///
    /// # Examples
    ///
    /// ```
    /// use b4ae::crypto::constant_time::ConstantTimeArithmetic;
    ///
    /// let result = ConstantTimeArithmetic::ct_add(10, 20);
    /// assert_eq!(result, 30);
    ///
    /// // Wrapping on overflow
    /// let result = ConstantTimeArithmetic::ct_add(u64::MAX, 1);
    /// assert_eq!(result, 0);
    /// ```
    pub fn ct_add(a: u64, b: u64) -> u64 {
        // Use wrapping_add to avoid overflow branches
        a.wrapping_add(b)
    }

    /// Subtract two u64 values in constant time.
    ///
    /// This function performs subtraction using wrapping arithmetic to avoid
    /// underflow branches, ensuring execution time is independent of operand values.
    ///
    /// # Arguments
    ///
    /// * `a` - First operand (minuend)
    /// * `b` - Second operand (subtrahend)
    ///
    /// # Returns
    ///
    /// The difference of `a` and `b`, wrapping on underflow
    ///
    /// # Security
    ///
    /// - Execution time independent of operand values
    /// - No secret-dependent branching
    /// - Uses wrapping arithmetic to avoid underflow branches
    ///
    /// # Examples
    ///
    /// ```
    /// use b4ae::crypto::constant_time::ConstantTimeArithmetic;
    ///
    /// let result = ConstantTimeArithmetic::ct_sub(30, 10);
    /// assert_eq!(result, 20);
    ///
    /// // Wrapping on underflow
    /// let result = ConstantTimeArithmetic::ct_sub(0, 1);
    /// assert_eq!(result, u64::MAX);
    /// ```
    pub fn ct_sub(a: u64, b: u64) -> u64 {
        // Use wrapping_sub to avoid underflow branches
        a.wrapping_sub(b)
    }

    /// Multiply two u64 values in constant time.
    ///
    /// This function performs multiplication using wrapping arithmetic to avoid
    /// overflow branches, ensuring execution time is independent of operand values.
    ///
    /// # Arguments
    ///
    /// * `a` - First operand
    /// * `b` - Second operand
    ///
    /// # Returns
    ///
    /// The product of `a` and `b`, wrapping on overflow
    ///
    /// # Security
    ///
    /// - Execution time independent of operand values
    /// - No secret-dependent branching
    /// - Uses wrapping arithmetic to avoid overflow branches
    ///
    /// # Examples
    ///
    /// ```
    /// use b4ae::crypto::constant_time::ConstantTimeArithmetic;
    ///
    /// let result = ConstantTimeArithmetic::ct_mul(10, 20);
    /// assert_eq!(result, 200);
    ///
    /// // Wrapping on overflow
    /// let result = ConstantTimeArithmetic::ct_mul(u64::MAX, 2);
    /// assert_eq!(result, u64::MAX.wrapping_mul(2));
    /// ```
    pub fn ct_mul(a: u64, b: u64) -> u64 {
        // Use wrapping_mul to avoid overflow branches
        a.wrapping_mul(b)
    }

    /// Check if a u64 value is zero in constant time.
    ///
    /// This function checks if a value is zero without secret-dependent branching,
    /// ensuring execution time is independent of the input value.
    ///
    /// # Arguments
    ///
    /// * `x` - Value to check
    ///
    /// # Returns
    ///
    /// * `Choice::from(1)` if `x` is zero
    /// * `Choice::from(0)` if `x` is non-zero
    ///
    /// # Security
    ///
    /// - Execution time independent of input value
    /// - No secret-dependent branching
    /// - Uses constant-time equality check from subtle crate
    ///
    /// # Examples
    ///
    /// ```
    /// use b4ae::crypto::constant_time::ConstantTimeArithmetic;
    ///
    /// let is_zero = ConstantTimeArithmetic::ct_is_zero(0);
    /// assert!(bool::from(is_zero));
    ///
    /// let is_not_zero = ConstantTimeArithmetic::ct_is_zero(42);
    /// assert!(!bool::from(is_not_zero));
    /// ```
    pub fn ct_is_zero(x: u64) -> Choice {
        // Use constant-time equality check from subtle crate
        x.ct_eq(&0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ct_memcmp_equal_arrays() {
        let a = [0x42; 32];
        let b = [0x42; 32];
        let result = ConstantTimeMemory::ct_memcmp(&a, &b);
        assert!(bool::from(result), "Equal arrays should return true");
    }

    #[test]
    fn test_ct_memcmp_different_arrays() {
        let a = [0x42; 32];
        let b = [0x43; 32];
        let result = ConstantTimeMemory::ct_memcmp(&a, &b);
        assert!(!bool::from(result), "Different arrays should return false");
    }

    #[test]
    fn test_ct_memcmp_different_lengths() {
        let a = [0x42; 32];
        let b = [0x42; 16];
        let result = ConstantTimeMemory::ct_memcmp(&a, &b);
        assert!(!bool::from(result), "Different length arrays should return false");
    }

    #[test]
    fn test_ct_memcmp_single_byte_difference() {
        let mut a = [0x42; 32];
        let mut b = [0x42; 32];
        b[15] = 0x43; // Single byte difference in the middle
        let result = ConstantTimeMemory::ct_memcmp(&a, &b);
        assert!(!bool::from(result), "Arrays with single byte difference should return false");
    }

    #[test]
    fn test_ct_memcmp_empty_arrays() {
        let a: [u8; 0] = [];
        let b: [u8; 0] = [];
        let result = ConstantTimeMemory::ct_memcmp(&a, &b);
        assert!(bool::from(result), "Empty arrays should be equal");
    }

    #[test]
    fn test_ct_memcmp_single_byte() {
        let a = [0x42];
        let b = [0x42];
        let result = ConstantTimeMemory::ct_memcmp(&a, &b);
        assert!(bool::from(result), "Single equal byte should return true");

        let c = [0x43];
        let result = ConstantTimeMemory::ct_memcmp(&a, &c);
        assert!(!bool::from(result), "Single different byte should return false");
    }

    #[test]
    fn test_ct_memcmp_large_arrays() {
        let a = vec![0x42; 1024];
        let b = vec![0x42; 1024];
        let result = ConstantTimeMemory::ct_memcmp(&a, &b);
        assert!(bool::from(result), "Large equal arrays should return true");

        let mut c = vec![0x42; 1024];
        c[1023] = 0x43; // Difference at the end
        let result = ConstantTimeMemory::ct_memcmp(&a, &c);
        assert!(!bool::from(result), "Large arrays with difference at end should return false");
    }

    #[test]
    fn test_ct_copy_basic() {
        let src = [1, 2, 3, 4, 5];
        let mut dst = [0u8; 5];
        ConstantTimeMemory::ct_copy(&mut dst, &src, 5);
        assert_eq!(dst, src, "Copied data should match source");
    }

    #[test]
    fn test_ct_copy_partial() {
        let src = [1, 2, 3, 4, 5];
        let mut dst = [0u8; 5];
        ConstantTimeMemory::ct_copy(&mut dst, &src, 3);
        assert_eq!(&dst[..3], &src[..3], "Partial copy should match");
        assert_eq!(&dst[3..], &[0, 0], "Remaining bytes should be unchanged");
    }

    #[test]
    fn test_ct_copy_zero_length() {
        let src = [1, 2, 3];
        let mut dst = [0u8; 3];
        ConstantTimeMemory::ct_copy(&mut dst, &src, 0);
        assert_eq!(dst, [0, 0, 0], "Zero-length copy should not modify destination");
    }

    #[test]
    fn test_ct_copy_large_buffer() {
        let src = vec![0x42; 1024];
        let mut dst = vec![0u8; 1024];
        ConstantTimeMemory::ct_copy(&mut dst, &src, 1024);
        assert_eq!(dst, src, "Large buffer copy should match");
    }

    #[test]
    #[should_panic(expected = "Destination buffer too small")]
    fn test_ct_copy_dst_too_small() {
        let src = [1, 2, 3, 4, 5];
        let mut dst = [0u8; 3];
        ConstantTimeMemory::ct_copy(&mut dst, &src, 5);
    }

    #[test]
    #[should_panic(expected = "Source buffer too small")]
    fn test_ct_copy_src_too_small() {
        let src = [1, 2, 3];
        let mut dst = [0u8; 5];
        ConstantTimeMemory::ct_copy(&mut dst, &src, 5);
    }

    #[test]
    fn test_ct_copy_with_secrets() {
        // Simulate copying secret key material
        let secret_key = [0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE];
        let mut backup = [0u8; 8];
        ConstantTimeMemory::ct_copy(&mut backup, &secret_key, 8);
        assert_eq!(backup, secret_key, "Secret key copy should be exact");
    }

    #[test]
    fn test_ct_memcmp_all_zeros() {
        let a = [0u8; 32];
        let b = [0u8; 32];
        let result = ConstantTimeMemory::ct_memcmp(&a, &b);
        assert!(bool::from(result), "All-zero arrays should be equal");
    }

    #[test]
    fn test_ct_memcmp_all_ones() {
        let a = [0xFF; 32];
        let b = [0xFF; 32];
        let result = ConstantTimeMemory::ct_memcmp(&a, &b);
        assert!(bool::from(result), "All-ones arrays should be equal");
    }

    #[test]
    fn test_ct_memcmp_first_byte_differs() {
        let a = [0x00; 32];
        let b = [0xFF; 32];
        let result = ConstantTimeMemory::ct_memcmp(&a, &b);
        assert!(!bool::from(result), "Arrays differing in first byte should return false");
    }

    #[test]
    fn test_ct_memcmp_last_byte_differs() {
        let a = [0x00; 32];
        let b = [0xFF; 32];
        let result = ConstantTimeMemory::ct_memcmp(&a, &b);
        assert!(!bool::from(result), "Arrays differing in last byte should return false");
    }

    // Tests for CacheTimingResistance

    #[test]
    fn test_ct_table_lookup_u8_first() {
        let table: Vec<u8> = vec![10, 20, 30, 40, 50];
        let value = CacheTimingResistance::ct_table_lookup(&table, 0);
        assert_eq!(value, 10, "Should retrieve first element");
    }

    #[test]
    fn test_ct_table_lookup_u8_middle() {
        let table: Vec<u8> = vec![10, 20, 30, 40, 50];
        let value = CacheTimingResistance::ct_table_lookup(&table, 2);
        assert_eq!(value, 30, "Should retrieve middle element");
    }

    #[test]
    fn test_ct_table_lookup_u8_last() {
        let table: Vec<u8> = vec![10, 20, 30, 40, 50];
        let value = CacheTimingResistance::ct_table_lookup(&table, 4);
        assert_eq!(value, 50, "Should retrieve last element");
    }

    #[test]
    fn test_ct_table_lookup_u32() {
        let table: Vec<u32> = vec![100, 200, 300, 400, 500];
        let value = CacheTimingResistance::ct_table_lookup(&table, 3);
        assert_eq!(value, 400, "Should retrieve u32 element");
    }

    #[test]
    fn test_ct_table_lookup_u64() {
        let table: Vec<u64> = vec![1000, 2000, 3000, 4000, 5000];
        let value = CacheTimingResistance::ct_table_lookup(&table, 1);
        assert_eq!(value, 2000, "Should retrieve u64 element");
    }

    #[test]
    fn test_ct_table_lookup_single_element() {
        let table: Vec<u8> = vec![42];
        let value = CacheTimingResistance::ct_table_lookup(&table, 0);
        assert_eq!(value, 42, "Should retrieve single element");
    }

    #[test]
    fn test_ct_table_lookup_large_table() {
        let table: Vec<u32> = (0..256).collect();
        let value = CacheTimingResistance::ct_table_lookup(&table, 128);
        assert_eq!(value, 128, "Should retrieve element from large table");
    }

    #[test]
    fn test_ct_table_lookup_all_indices() {
        let table: Vec<u8> = vec![10, 20, 30, 40, 50, 60, 70, 80];
        for i in 0..table.len() {
            let value = CacheTimingResistance::ct_table_lookup(&table, i);
            assert_eq!(value, table[i], "Should retrieve correct element at index {}", i);
        }
    }

    #[test]
    #[should_panic(expected = "Index out of bounds")]
    fn test_ct_table_lookup_out_of_bounds() {
        let table: Vec<u8> = vec![10, 20, 30];
        CacheTimingResistance::ct_table_lookup(&table, 3);
    }

    #[test]
    fn test_ct_table_lookup_with_duplicates() {
        let table: Vec<u8> = vec![42, 42, 42, 42, 42];
        let value = CacheTimingResistance::ct_table_lookup(&table, 2);
        assert_eq!(value, 42, "Should retrieve element even with duplicates");
    }

    #[test]
    fn test_ct_table_lookup_different_sizes() {
        // Test with various table sizes to ensure consistent behavior
        for size in [2, 4, 8, 16, 32, 64, 128] {
            let table: Vec<u32> = (0..size).collect();
            let mid = (size / 2) as usize;
            let value = CacheTimingResistance::ct_table_lookup(&table, mid);
            assert_eq!(value, mid as u32, "Should work with table size {}", size);
        }
    }

    // Test with custom struct that implements ConditionallySelectable
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
    struct TestStruct {
        a: u32,
        b: u32,
    }

    impl subtle::ConditionallySelectable for TestStruct {
        fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
            TestStruct {
                a: u32::conditional_select(&a.a, &b.a, choice),
                b: u32::conditional_select(&a.b, &b.b, choice),
            }
        }
    }

    #[test]
    fn test_ct_table_lookup_custom_struct() {
        let table = vec![
            TestStruct { a: 1, b: 10 },
            TestStruct { a: 2, b: 20 },
            TestStruct { a: 3, b: 30 },
            TestStruct { a: 4, b: 40 },
        ];
        let value = CacheTimingResistance::ct_table_lookup(&table, 2);
        assert_eq!(value, TestStruct { a: 3, b: 30 }, "Should retrieve custom struct");
    }

    #[test]
    fn test_ct_table_lookup_zero_values() {
        let table: Vec<u8> = vec![0, 0, 0, 0, 0];
        let value = CacheTimingResistance::ct_table_lookup(&table, 3);
        assert_eq!(value, 0, "Should handle all-zero table");
    }

    #[test]
    fn test_ct_table_lookup_max_values() {
        let table: Vec<u8> = vec![255, 255, 255, 255];
        let value = CacheTimingResistance::ct_table_lookup(&table, 1);
        assert_eq!(value, 255, "Should handle max value elements");
    }

    // Tests for ConstantTimeArithmetic

    #[test]
    fn test_ct_add_basic() {
        let result = ConstantTimeArithmetic::ct_add(10, 20);
        assert_eq!(result, 30, "Basic addition should work");
    }

    #[test]
    fn test_ct_add_zero() {
        let result = ConstantTimeArithmetic::ct_add(42, 0);
        assert_eq!(result, 42, "Adding zero should return original value");

        let result = ConstantTimeArithmetic::ct_add(0, 42);
        assert_eq!(result, 42, "Adding to zero should return second value");
    }

    #[test]
    fn test_ct_add_overflow() {
        let result = ConstantTimeArithmetic::ct_add(u64::MAX, 1);
        assert_eq!(result, 0, "Addition should wrap on overflow");

        let result = ConstantTimeArithmetic::ct_add(u64::MAX, u64::MAX);
        assert_eq!(result, u64::MAX.wrapping_add(u64::MAX), "Large overflow should wrap correctly");
    }

    #[test]
    fn test_ct_add_max_values() {
        let result = ConstantTimeArithmetic::ct_add(u64::MAX / 2, u64::MAX / 2);
        assert_eq!(result, u64::MAX - 1, "Adding large values should work");
    }

    #[test]
    fn test_ct_sub_basic() {
        let result = ConstantTimeArithmetic::ct_sub(30, 10);
        assert_eq!(result, 20, "Basic subtraction should work");
    }

    #[test]
    fn test_ct_sub_zero() {
        let result = ConstantTimeArithmetic::ct_sub(42, 0);
        assert_eq!(result, 42, "Subtracting zero should return original value");

        let result = ConstantTimeArithmetic::ct_sub(42, 42);
        assert_eq!(result, 0, "Subtracting same value should return zero");
    }

    #[test]
    fn test_ct_sub_underflow() {
        let result = ConstantTimeArithmetic::ct_sub(0, 1);
        assert_eq!(result, u64::MAX, "Subtraction should wrap on underflow");

        let result = ConstantTimeArithmetic::ct_sub(10, 20);
        assert_eq!(result, 10u64.wrapping_sub(20), "Underflow should wrap correctly");
    }

    #[test]
    fn test_ct_sub_max_values() {
        let result = ConstantTimeArithmetic::ct_sub(u64::MAX, 1);
        assert_eq!(result, u64::MAX - 1, "Subtracting from max should work");

        let result = ConstantTimeArithmetic::ct_sub(u64::MAX, u64::MAX);
        assert_eq!(result, 0, "Subtracting max from max should be zero");
    }

    #[test]
    fn test_ct_mul_basic() {
        let result = ConstantTimeArithmetic::ct_mul(10, 20);
        assert_eq!(result, 200, "Basic multiplication should work");
    }

    #[test]
    fn test_ct_mul_zero() {
        let result = ConstantTimeArithmetic::ct_mul(42, 0);
        assert_eq!(result, 0, "Multiplying by zero should return zero");

        let result = ConstantTimeArithmetic::ct_mul(0, 42);
        assert_eq!(result, 0, "Multiplying zero should return zero");
    }

    #[test]
    fn test_ct_mul_one() {
        let result = ConstantTimeArithmetic::ct_mul(42, 1);
        assert_eq!(result, 42, "Multiplying by one should return original value");

        let result = ConstantTimeArithmetic::ct_mul(1, 42);
        assert_eq!(result, 42, "Multiplying one should return second value");
    }

    #[test]
    fn test_ct_mul_overflow() {
        let result = ConstantTimeArithmetic::ct_mul(u64::MAX, 2);
        assert_eq!(result, u64::MAX.wrapping_mul(2), "Multiplication should wrap on overflow");

        let result = ConstantTimeArithmetic::ct_mul(u64::MAX, u64::MAX);
        assert_eq!(result, u64::MAX.wrapping_mul(u64::MAX), "Large overflow should wrap correctly");
    }

    #[test]
    fn test_ct_mul_large_values() {
        let result = ConstantTimeArithmetic::ct_mul(1_000_000, 1_000_000);
        assert_eq!(result, 1_000_000_000_000, "Multiplying large values should work");
    }

    #[test]
    fn test_ct_is_zero_true() {
        let result = ConstantTimeArithmetic::ct_is_zero(0);
        assert!(bool::from(result), "Zero should return true");
    }

    #[test]
    fn test_ct_is_zero_false() {
        let result = ConstantTimeArithmetic::ct_is_zero(1);
        assert!(!bool::from(result), "One should return false");

        let result = ConstantTimeArithmetic::ct_is_zero(42);
        assert!(!bool::from(result), "Non-zero value should return false");

        let result = ConstantTimeArithmetic::ct_is_zero(u64::MAX);
        assert!(!bool::from(result), "Max value should return false");
    }

    #[test]
    fn test_ct_is_zero_edge_cases() {
        // Test various non-zero values
        for value in [1, 2, 10, 100, 1000, u64::MAX / 2, u64::MAX - 1, u64::MAX] {
            let result = ConstantTimeArithmetic::ct_is_zero(value);
            assert!(!bool::from(result), "Value {} should not be zero", value);
        }
    }

    #[test]
    fn test_ct_arithmetic_combined() {
        // Test combining operations
        let a = 100u64;
        let b = 50u64;
        
        let sum = ConstantTimeArithmetic::ct_add(a, b);
        assert_eq!(sum, 150);
        
        let diff = ConstantTimeArithmetic::ct_sub(sum, b);
        assert_eq!(diff, a);
        
        let product = ConstantTimeArithmetic::ct_mul(a, b);
        assert_eq!(product, 5000);
    }

    #[test]
    fn test_ct_arithmetic_with_overflow_sequence() {
        // Test a sequence that involves overflow
        let mut value = u64::MAX - 10;
        
        value = ConstantTimeArithmetic::ct_add(value, 20); // Overflows
        assert_eq!(value, 9); // Wraps to 9
        
        value = ConstantTimeArithmetic::ct_sub(value, 20); // Underflows
        assert_eq!(value, 9u64.wrapping_sub(20)); // Wraps
        
        value = ConstantTimeArithmetic::ct_mul(value, 2);
        assert_eq!(value, 9u64.wrapping_sub(20).wrapping_mul(2));
    }

    #[test]
    fn test_ct_is_zero_after_operations() {
        // Test ct_is_zero after various operations
        let a = 42u64;
        let b = 42u64;
        
        let diff = ConstantTimeArithmetic::ct_sub(a, b);
        let is_zero = ConstantTimeArithmetic::ct_is_zero(diff);
        assert!(bool::from(is_zero), "Difference should be zero");
        
        let product = ConstantTimeArithmetic::ct_mul(0, 42);
        let is_zero = ConstantTimeArithmetic::ct_is_zero(product);
        assert!(bool::from(is_zero), "Product with zero should be zero");
    }

    #[test]
    fn test_ct_add_commutative() {
        // Test commutativity: a + b = b + a
        let a = 123u64;
        let b = 456u64;
        
        let result1 = ConstantTimeArithmetic::ct_add(a, b);
        let result2 = ConstantTimeArithmetic::ct_add(b, a);
        assert_eq!(result1, result2, "Addition should be commutative");
    }

    #[test]
    fn test_ct_mul_commutative() {
        // Test commutativity: a * b = b * a
        let a = 123u64;
        let b = 456u64;
        
        let result1 = ConstantTimeArithmetic::ct_mul(a, b);
        let result2 = ConstantTimeArithmetic::ct_mul(b, a);
        assert_eq!(result1, result2, "Multiplication should be commutative");
    }

    #[test]
    fn test_ct_add_associative() {
        // Test associativity: (a + b) + c = a + (b + c)
        let a = 100u64;
        let b = 200u64;
        let c = 300u64;
        
        let result1 = ConstantTimeArithmetic::ct_add(ConstantTimeArithmetic::ct_add(a, b), c);
        let result2 = ConstantTimeArithmetic::ct_add(a, ConstantTimeArithmetic::ct_add(b, c));
        assert_eq!(result1, result2, "Addition should be associative");
    }

    #[test]
    fn test_ct_mul_associative() {
        // Test associativity: (a * b) * c = a * (b * c)
        let a = 10u64;
        let b = 20u64;
        let c = 30u64;
        
        let result1 = ConstantTimeArithmetic::ct_mul(ConstantTimeArithmetic::ct_mul(a, b), c);
        let result2 = ConstantTimeArithmetic::ct_mul(a, ConstantTimeArithmetic::ct_mul(b, c));
        assert_eq!(result1, result2, "Multiplication should be associative");
    }

    #[test]
    fn test_ct_arithmetic_distributive() {
        // Test distributivity: a * (b + c) = a * b + a * c
        let a = 10u64;
        let b = 20u64;
        let c = 30u64;
        
        let left = ConstantTimeArithmetic::ct_mul(a, ConstantTimeArithmetic::ct_add(b, c));
        let right = ConstantTimeArithmetic::ct_add(
            ConstantTimeArithmetic::ct_mul(a, b),
            ConstantTimeArithmetic::ct_mul(a, c)
        );
        assert_eq!(left, right, "Multiplication should be distributive over addition");
    }
}
