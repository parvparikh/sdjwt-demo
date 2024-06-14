package org.example;

import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.File;
import java.io.IOException;
import java.util.Map;

public class SharedKeyManager {
    private static final String FILE_PATH = "C:\\Users\\Asus\\IdeaProjects\\demo_Authlete\\src\\main\\java\\org\\example\\shared_keys.json";
    private static Map<String, String> sharedKeys;

    static {
        try {
            loadSharedKeys();
        } catch (IOException e) {
            throw new RuntimeException("Failed to load shared keys", e);
        }
    }

    private static void loadSharedKeys() throws IOException {
        ObjectMapper objectMapper = new ObjectMapper();
        sharedKeys = objectMapper.readValue(new File(FILE_PATH), Map.class);
    }

    public static String getSharedKey(String userId) {
        return sharedKeys.get(userId);
    }

    public static void addOrUpdateSharedKey(String userId, String sharedKey) throws IOException {
        sharedKeys.put(userId, sharedKey);
        saveSharedKeys();
    }

    private static void saveSharedKeys() throws IOException {
        ObjectMapper objectMapper = new ObjectMapper();
        objectMapper.writeValue(new File(FILE_PATH), sharedKeys);
    }
}
