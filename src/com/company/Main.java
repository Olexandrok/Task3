package com.company;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.*;

public class Main {

    public static void main(String[] args) throws Exception {

        argumentsCheck(args);

        SecureRandom random = new SecureRandom();

        byte[] key = random.generateSeed(16);
        int computerMoveIndex = new Random().nextInt((args.length));
        String computerMove = args[computerMoveIndex];

        System.out.println("HMAC:\n" + HMAC_SHA256(key, computerMove));

        String userMove = "";

        boolean inputError = true;
        int userMoveIndex;
        printMenu(args);

        while (inputError) {
            try {
                userMoveIndex = new Scanner(System.in).nextInt();
                if (userMoveIndex == 0)
                    System.exit(-1);
                userMove = args[(userMoveIndex - 1)];
                inputError = false;
            } catch (ArrayIndexOutOfBoundsException | InputMismatchException e) {
                printMenu(args);
                inputError = true;
            }
        }

        System.out.println("Your move: " + userMove);
        System.out.println("Computer move: " + computerMove);

        String result = "";
        int index = getIndexOf(args, userMove);

        if (computerMoveIndex == (args.length/2))
            result = index > computerMoveIndex? "You win!": index < computerMoveIndex? "You lost!": "Draw!";
        else
            if (computerMoveIndex == index)
                result = "Draw!";
            else
                if (computerMoveIndex > args.length/2)
                    if(getIndexOf(Arrays.copyOfRange(args, computerMoveIndex - args.length/2, computerMoveIndex), userMove) == -1)
                        result = "You win!";
                    else
                        result = "You lost!";
                else
                    if (computerMoveIndex < args.length/2)
                        if(getIndexOf(Arrays.copyOfRange(args, computerMoveIndex, computerMoveIndex + args.length/2), userMove) != -1)
                            result = "You win!";
                        else
                            result = "You lost!";

        System.out.println(result);
        System.out.println("HMAC key: " + toHexString(key));
    }

    public static void argumentsCheck(String[] args){
        if (args.length <3) {
            System.out.println("Incorrect input: Too few arguments. At least 3 arguments are required.");
            System.out.println("Example of correct input: \"Rock Paper Scissors\"");
            System.exit(-1);
        } else
        if (args.length%2 != 1){
            System.out.println("Incorrect input: Even number of arguments. Odd number of arguments are required.");
            System.out.println("Example of correct input: \"Rock Paper Scissors\"");
            System.exit(-1);
        } else
        if (isNotUnique(args)){
            System.out.println("Incorrect input: At least two similar arguments. Unique arguments are required.");
            System.out.println("Example of correct input: \"Rock Paper Scissors\"");
            System.exit(-1);
        }
    }
    public static void printMenu(String[] input){
        System.out.println("Available moves:");
        int i = 1;
        for (Object element: input)
            System.out.println(i++ + " - " + element);
        System.out.println("0 - exit");
        System.out.print("Enter your move: ");
    }

    public static int getIndexOf(String[] input, String elem){
        int index = -1;
        for (int i = 0; i < input.length; i++)
            if (input[i].equals(elem))
                index = i;
        return index;
    }
    public static boolean isNotUnique(String[] args){
        for (int i = 0; i < args.length - 1; i++)
            for(int j = i + 1; j < args.length; j++)
                if (args[j].equals(args[i]))
                    return true;
        return false;
    }

    public static String HMAC_SHA256(byte[] key, String data)
            throws NoSuchAlgorithmException, InvalidKeyException {
        SecretKeySpec secretKeySpec = new SecretKeySpec(key, "HMACSHA256");
        Mac mac = Mac.getInstance("HMACSHA256");
        mac.init(secretKeySpec);
        return toHexString(mac.doFinal(data.getBytes()));
    }

    private static String toHexString(byte[] bytes) {
        Formatter formatter = new Formatter();
        for (byte b : bytes) {
            formatter.format("%02x", b);
        }
        return formatter.toString().toUpperCase();
    }
}
