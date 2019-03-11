package com.datatheorem.android.trustkit.config;

import android.support.test.runner.AndroidJUnit4;
import org.junit.Test;
import org.junit.runner.RunWith;

import static org.junit.Assert.assertTrue;

@RunWith(AndroidJUnit4.class)
public class DomainValidatorTest {

  @Test
  public void testValidForDataTestDotCom() {
    // Given
    final DomainValidator validator = DomainValidator.getInstance(true);

    // When
    final boolean isValid = validator.isValid("www.test.com");

    // Then
    assertTrue("www.test.com domain should be valid", isValid);
  }

  @Test
  public void testValidForLocalhost() {
    // Given
    final DomainValidator validator = DomainValidator.getInstance(true);

    // When
    final boolean isValid = validator.isValid("localhost");

    // Then
    assertTrue("localhost domain should be valid", isValid);
  }

  @Test
  public void testValidFor127Dot0Dot0Dot1() {
    // Given
    final DomainValidator validator = DomainValidator.getInstance(true);

    // When
    final boolean isValid = validator.isValid("127.0.0.1");

    // Then
    assertTrue("127.0.0.1 domain should be valid", isValid);
  }

}