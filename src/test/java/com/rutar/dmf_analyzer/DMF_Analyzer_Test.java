package com.rutar.dmf_analyzer;

import java.io.*;
import org.junit.jupiter.api.*;

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
    "src/test/resources/com/rutar/dmf_analyzer/dmf/";

///////////////////////////////////////////////////////////////////////////////

@Test
@DisplayName("Should pass")
void should_Answer_With_True()
    { assertTrue(true); }

///////////////////////////////////////////////////////////////////////////////

@Test
@DisplayName("File ReadMe.txt exist")
void file_Empty_Exist()
    { File file = new File(RESOURCES_PATH + "ReadMe.txt");
      assertTrue(file.exists()); }

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
