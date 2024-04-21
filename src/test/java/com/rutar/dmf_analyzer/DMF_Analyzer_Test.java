package com.rutar.dmf_analyzer;

import java.io.*;
import org.junit.jupiter.api.*;
import org.junit.jupiter.params.*;
import org.junit.jupiter.params.provider.*;

import static org.junit.jupiter.api.Assertions.*;

// ............................................................................

/**
 * Клас DMF_Analyzer_Test
 * @author Rutar_Andriy
 * 21.04.2024
 */

@DisplayName("Main test class")
public class DMF_Analyzer_Test {

private static final String RESOURCES_PATH =
    "src/test/resources/com/rutar/dmf_analyzer/";

///////////////////////////////////////////////////////////////////////////////

@Test
@DisplayName("Should pass")
void should_Answer_With_True()
    { assertTrue(true); }

///////////////////////////////////////////////////////////////////////////////

@Test
@DisplayName("File .empty exist")
void file_Empty_Exist()
    { File file = new File(RESOURCES_PATH + ".empty");
      assertTrue(file.exists()); }

///////////////////////////////////////////////////////////////////////////////

@Nested
@DisplayName("# Library test class")
class Library_Test {

    // ........................................................................

    @Test
    @DisplayName("1 + 1 = 2")
    void one_Plus_One() {
        assertEquals(2, DMF_Analyzer.sum(1, 1));
    }

    // ........................................................................

    @DisplayName("sum")
    @ParameterizedTest(name = "({0} + {1}) = {2}")
    @CsvSource(
        { "   -1,  -1,  -2 ",
          "   16,   9,  25 ",
          "   -8,  15,   7 ",
          "   61, 304, 365 ",
          " 1024, -83, 941 "  })
    void sum (int n1, int n2, int sum)
        { assertEquals(sum, DMF_Analyzer.sum(n1, n2)); }

    // ........................................................................

    @DisplayName("sum")
    @ParameterizedTest(name = "({0} + {1} + {2} + {3} + {4}) = {5}")
    @CsvSource(
        { "    1,    2,   3,    4,   5,  15 ",
          "   10,    9,   8,    7,   6,  40 ",
          " 1000, -900, 800, -700, 600, 800 " })
    void sum (int n1, int n2, int n3, int n4, int n5, int sum)
        { assertEquals(sum, DMF_Analyzer.sum(n1, n2, n3, n4, n5)); }

    // ........................................................................

    @DisplayName("product")
    @ParameterizedTest(name = "({0} * {1}) = {2}")
    @CsvSource(
        { "    2,  3,    6 ",
          "    6,  8,   48 ",
          "   -7, -3,   21 ",
          "   63,  0,    0 ",
          " 1024,  8, 8192 "  })
    void product (int n1, int n2, int product)
        { assertEquals(product, DMF_Analyzer.product(n1, n2)); }

    // ........................................................................

    @DisplayName("product")
    @ParameterizedTest(name = "({0} * {1} * {2} * {3} * {4}) = {5}")
    @CsvSource(
        { "  1,  1,  1,  1,  1,      1 ",
          "  3,  5,  7,  9, 11,  10395 ",
          " 10, 10, 10, 10, 10, 100000 " })
    void product (int n1, int n2, int n3, int n4, int n5, int product)
        { assertEquals(product, DMF_Analyzer.product(n1, n2, n3, n4, n5)); }

    // ........................................................................

    @DisplayName("arithmeticMean")
    @ParameterizedTest(name = "({0}, {1}, {2}, {3}, {4}) = {5}")
    @CsvSource(
        { "  3, 5,  7,   9, 11,  7.0 ",
          "  2, 5,  7,   9, 11,  6.8 ",
          " 16, 4, 26, 167, -7, 41.2 " })
    void arithmeticMean (int n1, int n2, int n3, int n4, int n5, double mean)
        { assertEquals(mean, DMF_Analyzer
         .arithmeticMean(n1, n2, n3, n4, n5), 0.001); }

    // ........................................................................

    @DisplayName("quadraticMean")
    @ParameterizedTest(name = "({0}, {1}, {2}, {3}, {4}) = {5}")
    @CsvSource(
        { "  1, 1,  1,   1,  1,      1 ",
          "  3, 5,  7,   9, 11,  7.550 ",
          " 16, 4, 96, 103, -5, 63.438 " })
    void quadraticMean (int n1, int n2, int n3, int n4, int n5, double mean)
        { assertEquals(mean, DMF_Analyzer
         .quadraticMean(n1, n2, n3, n4, n5), 0.001); }

}

///////////////////////////////////////////////////////////////////////////////
    
// @Test
// @Disabled("skipped")
// @DisplayName("Should skip")
// void should_Skip() {
//     fail("This error will be skipped");
// }

///////////////////////////////////////////////////////////////////////////////

// @Test
// @DisplayName("Should fail")
// void should_Fail() {
//     fail("Some error ...");
// }

// Кінець класу DMF_Analyzer_Test /////////////////////////////////////////////

}
