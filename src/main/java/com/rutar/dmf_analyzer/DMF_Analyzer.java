package com.rutar.dmf_analyzer;

import java.io.*;
import java.nio.*;
import java.util.zip.*;

import static java.nio.ByteOrder.*;

/**
 * Клас DMF_Analyzer
 * @author Rutar_Andriy
 * 09.04.2024
 */

public class DMF_Analyzer {

///////////////////////////////////////////////////////////////////////////////
// Змінні, які реалізують основний функціонал компонента //////////////////////

private Signature           signature;         // Мітка розпізнавання DMF файлу
private Header_Structure    header_structure;                 // Блок заголовку
private Layers_Structure    layers_structure;                     // Блок шарів
private Params_Structure    params_structure;                // Блок параметрів
private Symbols_Structure   symbols_structure;           // Блок умовних знаків
private Passwords_Structure passwords_structure;                // Блок паролів
private Objects_Structure   objects_structure;                 // Блок об'єктів

///////////////////////////////////////////////////////////////////////////////
// Допоміжні змінні /////////////////////////////////////////// ///////////////

private InputStream is;              // Потік для зчитування даних із DMF файлу
private final ByteArrayOutputStream temp = new ByteArrayOutputStream(); // доп.

///////////////////////////////////////////////////////////////////////////////

/**
 * Базовий аналіз DMF файлу
 * @param file *.dmf файл
 * @throws Exception якщо в процесі аналізування сталася критична помилка
 */
public void analyze (File file) throws Exception { analyze(file, false); }

///////////////////////////////////////////////////////////////////////////////

/**
 * Глибокий аналіз DMF файлу
 * @param file *.dmf файл
 * @param deep використовувати глибокий аналіз файлу
 * @throws Exception якщо в процесі аналізування сталася критична помилка
 */
public void analyze (File file, boolean deep) throws Exception {

InflaterInputStream iis = null;

// Починаємо зчитувати файл
try (FileInputStream fis = new FileInputStream(file)) {

// Ініціалізація потоку зчитування даних
is = fis;

// Зчитування сигнатури DMF файлу
signature = new Signature();
signature.read();

// Визначаємо тип сигнатури
int signature_type = signature.getType();

// Якщо файл стиснений, то створюємо декомпресійний потік
if (signature_type == Signature.UNENCRYPTED_COMPRESSED ||
    signature_type == Signature.ENCRYPTED_COMPRESSED) {

    iis = new InflaterInputStream(fis);
    is = iis;

}

// Зчитуємо блок заголовку
header_structure = new Header_Structure();
header_structure.read();
if (deep) { header_structure.analyze(); }

// Зчитуємо блок шарів
layers_structure = new Layers_Structure();
layers_structure.read();
if (deep) { layers_structure.analyze(); }

// Зчитуємо блок параметрів
params_structure = new Params_Structure();
params_structure.read();
if (deep) { params_structure.analyze(); }

// Зчитуємо блок умовних знаків
symbols_structure = new Symbols_Structure();
symbols_structure.read();
if (deep) { symbols_structure.analyze(); }

// Якщо файл містить паролі, то зчитуємо блок паролів
if (signature_type == Signature.ENCRYPTED_UNCOMPRESSED ||
    signature_type == Signature.ENCRYPTED_COMPRESSED) {

    passwords_structure = new Passwords_Structure();
    passwords_structure.read();
    if (deep) { passwords_structure.analyze(); }

}

// Зчитуємо блок об'єктів
objects_structure = new Objects_Structure();
objects_structure.read();
if (deep) { objects_structure.analyze(); }

}

catch (Exception e) { 
    switch (e.getMessage()) {
        case "D" -> { throw new Exception("DMF deep analyze error"); }
        default  -> { throw new Exception("DMF analyze error"); } } }

finally { // Закриваємо декомпресійний потік, якщо він ініціалізований
          if (iis != null) { iis.close(); }
          // Закриваємо основний потік зчитування даних
          is.close(); }

}

///////////////////////////////////////////////////////////////////////////////
// Getter'и - повертають складові блоки DMF файлу /////////////////////////////
///////////////////////////////////////////////////////////////////////////////

/**
 * Отримання сигнатури
 * @return сигнатура
 */
public Signature getSignature()
    { return signature; }

///////////////////////////////////////////////////////////////////////////////

/**
 * Отримання блоку заголовку
 * @return блок заголовку
 */
public Header_Structure getHeaderStructure()
    { return header_structure; }

///////////////////////////////////////////////////////////////////////////////

/**
 * Отримання блоку шарів
 * @return блок шарів
 */
public Layers_Structure getLayersStructure()
    { return layers_structure; }

///////////////////////////////////////////////////////////////////////////////

/**
 * Отримання блоку параметрів
 * @return блок параметрів
 */
public Params_Structure getParamsStructure()
    { return params_structure; }

///////////////////////////////////////////////////////////////////////////////

/**
 * Отримання блоку умовних знаків
 * @return блок умовних знаків
 */
public Symbols_Structure getSymbolsStructure()
    { return symbols_structure; }

///////////////////////////////////////////////////////////////////////////////

/**
 * Отримання блоку паролів
 * @return блок паролів
 */
public Passwords_Structure getPasswordsStructure()
    { return passwords_structure; }

///////////////////////////////////////////////////////////////////////////////

/**
 * Отримання блоку об'єктів
 * @return блок об'єктів
 */
public Objects_Structure getObjectsStructure()
    { return objects_structure; }

///////////////////////////////////////////////////////////////////////////////
// Базовий абстрактний клас, який представляє довільний блок DMF файлу ////////
///////////////////////////////////////////////////////////////////////////////

private abstract class Basic_Structure {

protected int    structure_size = -1;
protected byte[] structure_data = null;

protected final ByteArrayOutputStream raw_data = new ByteArrayOutputStream();

///////////////////////////////////////////////////////////////////////////////

/**
 * Зчитування блоку даних
 * @throws Exception якщо в процесі зчитування сталася критична помилка
 */
public void read() throws Exception {

try { byte[] size = readAndCollectBytes(4);
      structure_size = getInteger(size);
      raw_data.write(size);

      structure_data = readAndCollectBytes(structure_size);
      raw_data.write(structure_data); }

catch (IOException e) { throw new Exception(); }

}

///////////////////////////////////////////////////////////////////////////////

/**
 * Аналізування блоку даних
 * @throws Exception якщо в процесі аналізування сталася критична помилка
 */
public void analyze() throws Exception {}

///////////////////////////////////////////////////////////////////////////////

/**
 * Отримання розміру блоку даних
 * @return розмір блоку даних
 */
public int getStructureSize() { return structure_size; }

///////////////////////////////////////////////////////////////////////////////

/**
 * Отримання блоку даних
 * @return блок даних
 */
public byte[] getStructureData() { return structure_data; }

///////////////////////////////////////////////////////////////////////////////

/**
 * Отримання сирих (необроблених) даних
 * @return сирі (необроблені) дані
 */
public byte[] getRawData() { return raw_data.toByteArray(); }

}

///////////////////////////////////////////////////////////////////////////////
// Signature - мітка розпізнавання DMF файлу //////////////////////////////////
///////////////////////////////////////////////////////////////////////////////

/** Сигнатура - мітка розпізнавання DMF файлу */
public class Signature {

/** Нестиснений та незапаролений файл */
public static final int UNENCRYPTED_UNCOMPRESSED = 0;
/** Стиснений   та незапаролений файл */
public static final int UNENCRYPTED_COMPRESSED = 1;
/** Нестиснений та запаролений файл */
public static final int ENCRYPTED_UNCOMPRESSED = 2;
/** Стиснений   та запаролений файл */
public static final int ENCRYPTED_COMPRESSED = 3;

// ............................................................................

private byte[] signature_data = null;

///////////////////////////////////////////////////////////////////////////////

/** Зчитування сигнатури */
public void read() { signature_data = readBytes(32);
                     collectBytes(signature_data); }

///////////////////////////////////////////////////////////////////////////////

/**
 * Отримання типу сигнатури
 * @return UNENCRYPTED_UNCOMPRESSED, UNENCRYPTED_COMPRESSED, 
 * ENCRYPTED_UNCOMPRESSED або ENCRYPTED_COMPRESSED
 */
public int getType() {
    
    int encryption_type;
    int compression_type;
    
    if (signature_data[26] == 53) { encryption_type  = 1; }
    else                          { encryption_type  = 0; }

    if (signature_data[28] == 67) { compression_type = 1; }
    else                          { compression_type = 0; }
    
    return encryption_type * 2 + compression_type;

}

///////////////////////////////////////////////////////////////////////////////

/**
 * Задання типу сигнатури
 * @param type UNENCRYPTED_UNCOMPRESSED, UNENCRYPTED_COMPRESSED, 
 * ENCRYPTED_UNCOMPRESSED або ENCRYPTED_COMPRESSED
 */
public void setType (int type) {

    switch (type) {
        case UNENCRYPTED_UNCOMPRESSED -> { signature_data[26] = 48;
                                           signature_data[28] = 32; }
        case UNENCRYPTED_COMPRESSED   -> { signature_data[26] = 48;
                                           signature_data[28] = 67; }
        case ENCRYPTED_UNCOMPRESSED   -> { signature_data[26] = 53;
                                           signature_data[28] = 32; }
        default                       -> { signature_data[26] = 53;
                                           signature_data[28] = 67; } } }

///////////////////////////////////////////////////////////////////////////////

/**
 * Отримання сирих (необроблених) даних
 * @return сирі (необроблені) дані
 */
public byte[] getRawData() { return signature_data; }

}

///////////////////////////////////////////////////////////////////////////////

/** Блок заголовку - мітить загальну інформацію про файл */
public class Header_Structure extends Basic_Structure {}

// ............................................................................

/** Блок шарів - містить інформацію про всі шари */
public class Layers_Structure extends Basic_Structure {}

// ............................................................................

/** Блок параметрів - містить інформацію про всі параметри */
public class Params_Structure extends Basic_Structure {}

// ............................................................................

/** Блок умовних знаків - містить інформацію про всі умовні знаки */
public class Symbols_Structure extends Basic_Structure {}

// ............................................................................

/** Блок паролів - містить зашифровану інформацію про паролі */
public class Passwords_Structure extends Basic_Structure {}

// ............................................................................

/** Блок об'єктів - список усіх об'єктів разом із їхніми властивостями */
public class Objects_Structure extends Basic_Structure {

@Override
public void read() throws Exception {

while (is.available() > 0) {

    byte[] size = readAndCollectBytes(4);
    structure_size = getInteger(size);
    
    raw_data.write(size);
    raw_data.write(readAndCollectBytes(structure_size));
    
}

structure_size = raw_data.size();
structure_data = raw_data.toByteArray();

}
}

///////////////////////////////////////////////////////////////////////////////
// Допоміжні методи ///////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////

// Читання байтів
private byte[] readBytes (int lenght)
    { return readBytes(lenght, false); }

// ............................................................................

// Читання байтів із можливістю їх виведення в консоль
private byte[] readBytes (int lenght, boolean print) {

try { var data = is.readNBytes(lenght); 
      if (print) { printBytes(data); }
      return data; }

catch (IOException e) { return null; } }

///////////////////////////////////////////////////////////////////////////////

// Запис байтів
private void collectBytes (byte[] data)
    { collectBytes(data, false); }

// ............................................................................

// Запис байтів із можливістю їх виведення в консоль
private void collectBytes (byte[] data, boolean print) {
    
    try { temp.write(data); }
    catch (IOException e) {  }
    
    if (print) { printBytes(data); } }

///////////////////////////////////////////////////////////////////////////////

// Читання та запис байтів
private byte[] readAndCollectBytes (int lenght)
    { return readAndCollectBytes(lenght, false); }

// ............................................................................

// Читання та запис байтів із можливістю їх виведення в консоль
private byte[] readAndCollectBytes (int lenght, boolean print) {

    var data = readBytes(lenght, print);
    collectBytes(data);
    
    return data; }

///////////////////////////////////////////////////////////////////////////////

// Виведення байтів у консоль
public void printBytes (byte[] bytes) { printBytes(bytes, true); }

// ............................................................................

// Виведення байтів у консоль із можливість вимкнути перенесення нового рядка
public void printBytes (byte[] bytes, boolean nextLine) {
    for (byte b : bytes) { System.out.print(byteToHex(b)); }
    if (nextLine) { System.out.println(); }
}

///////////////////////////////////////////////////////////////////////////////

// Конвертування байту в HEX-строку
private String byteToHex (byte b) {
    return String.format("%02X", b & 0xff) + " ";
}

///////////////////////////////////////////////////////////////////////////////

// Конвертування масиву байт в ціле число
private int getInteger (byte[] data) {
    return ByteBuffer.wrap(data).order(LITTLE_ENDIAN).getInt();
}

// ............................................................................

// Конвертування масиву байт в строку
private String getString (byte[] data) {
    try { data = new String(data, "Windows-1251").getBytes();
          return new String(data, "Windows-1251"); }
    catch (UnsupportedEncodingException e) { return null; }

}

// Кінець класу DMF_Analyzer //////////////////////////////////////////////////

}