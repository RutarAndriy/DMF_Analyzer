package com.rutar.dmf_analyzer;

// ............................................................................

/**
 * Клас DMF_Analyzer
 * @author Rutar_Andriy
 * 21.04.2024
 */

public class DMF_Analyzer {

///////////////////////////////////////////////////////////////////////////////

/**
 * Метод підраховує суму вхідних чисел
 * @param numbers масив/перелік вхідних чисел
 * @return сума вхідних чисел
 */
public static long sum (int ... numbers) {

    if (numbers == null) { throw new NullPointerException(); }
    else if (numbers.length == 0) { throw new IllegalArgumentException(); }
    else if (numbers.length == 1) { return numbers[0]; }

    else {

        long result = numbers[0];

        for (int z = 1; z < numbers.length; z++) {
            result += numbers[z];
        }

        return result;
    }    
}

///////////////////////////////////////////////////////////////////////////////

/**
 * Метод підраховує добуток вхідних чисел
 * @param numbers масив/перелік вхідних чисел
 * @return добуток вхідних чисел
 */
public static long product (int ... numbers) {

    if (numbers == null) { throw new NullPointerException(); }
    else if (numbers.length == 0) { throw new IllegalArgumentException(); }
    else if (numbers.length == 1) { return numbers[0]; }

    else {

        long result = numbers[0];

        for (int z = 1; z < numbers.length; z++) {
            result *= numbers[z];
        }

        return result;
    }
}

///////////////////////////////////////////////////////////////////////////////

/**
 * Метод рахує середнє арифметичне значення
 * @param numbers масив/перелік вхідних чисел
 * @return середнє арифметичне значення
 */
public static double arithmeticMean (int ... numbers) {

    if (numbers == null) { throw new NullPointerException(); }
    else if (numbers.length == 0) { throw new IllegalArgumentException(); }
    else if (numbers.length == 1) { return numbers[0]; }

    else {

        return sum(numbers) * 1d / numbers.length;

    }
}

///////////////////////////////////////////////////////////////////////////////

/**
 * Метод рахує середнє квадратичне значення
 * @param numbers масив/перелік вхідних чисел
 * @return середнє квадратичне значення
 */
public static double quadraticMean (int ... numbers) {

    if (numbers == null) { throw new NullPointerException(); }
    else if (numbers.length == 0) { throw new IllegalArgumentException(); }
    else if (numbers.length == 1) { return numbers[0]; }

    else {

        for (int z = 0; z < numbers.length; z++)
            { numbers[z] *= numbers[z]; }
        
        return Math.sqrt(sum(numbers) * 1d / numbers.length);
    }
}

// Кінець класу DMF_Analyzer //////////////////////////////////////////////////

}
