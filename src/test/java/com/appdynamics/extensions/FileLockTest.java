package com.appdynamics.extensions;

import java.io.*;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.nio.channels.OverlappingFileLockException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;

/**
 * Created by kunal.gupta on 9/24/15.
 */
public class FileLockTest {


    public static void main(String[] args){

        try {

            File file = new File(String.valueOf(FileLockTest.class.getResource("conf/snmp-engine.properties")));

            // Creates a random access file stream to read from, and optionally to write to
            FileChannel channel = new RandomAccessFile(file, "rw").getChannel();

            // Acquire an exclusive lock on this channel's file (blocks until lock can be retrieved)
            System.out.println("Trying to acquire lock");
            FileLock lock = channel.lock();
            System.out.println("Lock acquired");
            // Attempts to acquire an exclusive lock on this channel's file (returns null or throws
            // an exception if the file is already locked.
            try {
                try {
                    BufferedReader br = Files.newBufferedReader(Paths.get(String.valueOf(FileLockTest.class.getResource("conf/snmp-engine.properties"))), StandardCharsets.UTF_8);
                    System.out.println(br.readLine());
                    System.out.println("Read complete");
                    Thread.currentThread().sleep(60000);
                    br.close();
                } catch (InterruptedException e) {
                    e.printStackTrace();
                }

            }
            catch (OverlappingFileLockException e) {
                // thrown when an attempt is made to acquire a lock on a a file that overlaps
                // a region already locked by the same JVM or when another thread is already
                // waiting to lock an overlapping region of the same file
                System.out.println("Overlapping File Lock Error: " + e.getMessage());
            }

            // release the lock
            lock.release();

            // close the channel
            channel.close();

        }
        catch (IOException e) {
            System.out.println("I/O Error: " + e.getMessage());
        }

    }

    }
