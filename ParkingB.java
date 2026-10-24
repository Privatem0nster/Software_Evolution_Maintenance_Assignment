import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.SecureRandom;
import java.security.spec.KeySpec;
import java.time.*;
import java.time.format.DateTimeFormatter;
import java.util.*;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

public class ParkingB {
    private static final String DATA_FILE = "parking_data.tsv";
    private static final ZoneId KL_ZONE = ZoneId.of("Asia/Kuala_Lumpur");
    private static final DateTimeFormatter DT_FORMAT = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");
    private static final Scanner SCANNER = new Scanner(System.in);

    // =========================================================================
    // DATA MODELS (Records)
    // =========================================================================
    public static class User {
        public String username;
        public String saltHex;
        public String hashHex;
        public long balanceSen;

        public User(String username, String saltHex, String hashHex, long balanceSen) {
            this.username = username;
            this.saltHex = saltHex;
            this.hashHex = hashHex;
            this.balanceSen = balanceSen;
        }
    }

    public static class Vehicle {
        public String plate;
        public String username;

        public Vehicle(String plate, String username) {
            this.plate = plate;
            this.username = username;
        }
    }

    public static class ParkingSession {
        public String sessionId;
        public String username;
        public String plate;
        public String location;
        public long startTimeMillis;
        public long expiryTimeMillis;
        public int totalDurationMinutes;

        public ParkingSession(String sessionId, String username, String plate, String location,
                              long startTimeMillis, long expiryTimeMillis, int totalDurationMinutes) {
            this.sessionId = sessionId;
            this.username = username;
            this.plate = plate;
            this.location = location;
            this.startTimeMillis = startTimeMillis;
            this.expiryTimeMillis = expiryTimeMillis;
            this.totalDurationMinutes = totalDurationMinutes;
        }
    }

    public static class Receipt {
        public String receiptId;
        public String username;
        public String type; // "PARK" or "EXTEND"
        public long amountSen;
        public String sessionId;
        public long paymentTimeMillis;
        public long expiryTimeMillis;

        public Receipt(String receiptId, String username, String type, long amountSen,
                       String sessionId, long paymentTimeMillis, long expiryTimeMillis) {
            this.receiptId = receiptId;
            this.username = username;
            this.type = type;
            this.amountSen = amountSen;
            this.sessionId = sessionId;
            this.paymentTimeMillis = paymentTimeMillis;
            this.expiryTimeMillis = expiryTimeMillis;
        }
    }

    public static class Data {
        public List<User> users = new ArrayList<>();
        public List<Vehicle> vehicles = new ArrayList<>();
        public List<ParkingSession> sessions = new ArrayList<>();
        public List<Receipt> receipts = new ArrayList<>();
    }

    // =========================================================================
    // STORAGE CLASS (UTF-8 TSV & Atomic Updates)
    // =========================================================================
    public static class Store {
        public static Data loadData() {
            Data data = new Data();
            File file = new File(DATA_FILE);
            if (!file.exists()) {
                return data;
            }
            try (BufferedReader reader = Files.newBufferedReader(file.toPath(), StandardCharsets.UTF_8)) {
                String line;
                while ((line = reader.readLine()) != null) {
                    if (line.trim().isEmpty()) continue;
                    String[] parts = line.split("\t", -1);
                    String type = parts[0];
                    switch (type) {
                        case "USER":
                            if (parts.length >= 5) {
                                data.users.add(new User(parts[1], parts[2], parts[3], Long.parseLong(parts[4])));
                            }
                            break;
                        case "VEHICLE":
                            if (parts.length >= 3) {
                                data.vehicles.add(new Vehicle(parts[1], parts[2]));
                            }
                            break;
                        case "SESSION":
                            if (parts.length >= 8) {
                                data.sessions.add(new ParkingSession(
                                        parts[1], parts[2], parts[3], parts[4],
                                        Long.parseLong(parts[5]), Long.parseLong(parts[6]), Integer.parseInt(parts[7])
                                ));
                            }
                            break;
                        case "RECEIPT":
                            if (parts.length >= 8) {
                                data.receipts.add(new Receipt(
                                        parts[1], parts[2], parts[3], Long.parseLong(parts[4]),
                                        parts[5], Long.parseLong(parts[6]), Long.parseLong(parts[7])
                                ));
                            }
                            break;
                    }
                }
            } catch (IOException e) {
                System.out.println("[Error] Failed to load storage: " + e.getMessage());
            }
            return data;
        }

        public static boolean saveData(Data data) {
            File file = new File(DATA_FILE);
            File tempFile = new File(DATA_FILE + ".tmp");
            try (BufferedWriter writer = Files.newBufferedWriter(tempFile.toPath(), StandardCharsets.UTF_8)) {
                for (User u : data.users) {
                    writer.write(String.join("\t", "USER", u.username, u.saltHex, u.hashHex, String.valueOf(u.balanceSen)));
                    writer.newLine();
                }
                for (Vehicle v : data.vehicles) {
                    writer.write(String.join("\t", "VEHICLE", v.plate, v.username));
                    writer.newLine();
                }
                for (ParkingSession s : data.sessions) {
                    writer.write(String.join("\t", "SESSION", s.sessionId, s.username, s.plate, s.location,
                            String.valueOf(s.startTimeMillis), String.valueOf(s.expiryTimeMillis), String.valueOf(s.totalDurationMinutes)));
                    writer.newLine();
                }
                for (Receipt r : data.receipts) {
                    writer.write(String.join("\t", "RECEIPT", r.receiptId, r.username, r.type,
                            String.valueOf(r.amountSen), r.sessionId, String.valueOf(r.paymentTimeMillis), String.valueOf(r.expiryTimeMillis)));
                    writer.newLine();
                }
            } catch (IOException e) {
                System.out.println("[Error] Failed to write temporary storage: " + e.getMessage());
                tempFile.delete();
                return false;
            }

            try {
                Files.move(tempFile.toPath(), file.toPath(), StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
            } catch (Exception e) {
                try {
                    Files.move(tempFile.toPath(), file.toPath(), StandardCopyOption.REPLACE_EXISTING);
                } catch (IOException ex) {
                    System.out.println("[Error] Failed to save storage atomically: " + ex.getMessage());
                    tempFile.delete();
                    return false;
                }
            }
            return true;
        }
    }

    // =========================================================================
    // SECURITY UTILS (PBKDF2-HMAC-SHA256)
    // =========================================================================
    public static class SecurityUtils {
        private static final SecureRandom RANDOM = new SecureRandom();

        public static String generateSaltHex() {
            byte[] salt = new byte[16];
            RANDOM.nextBytes(salt);
            return bytesToHex(salt);
        }

        public static String hashPassword(String password, String saltHex) {
            try {
                byte[] salt = hexToBytes(saltHex);
                KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 120000, 256);
                SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
                byte[] hash = factory.generateSecret(spec).getEncoded();
                return bytesToHex(hash);
            } catch (Exception e) {
                throw new RuntimeException("Error hashing password", e);
            }
        }

        public static boolean verifyPassword(String password, String saltHex, String expectedHashHex) {
            String computedHash = hashPassword(password, saltHex);
            return computedHash.equals(expectedHashHex);
        }

        private static String bytesToHex(byte[] bytes) {
            StringBuilder sb = new StringBuilder();
            for (byte b : bytes) {
                sb.append(String.format("%02x", b));
            }
            return sb.toString();
        }

        private static byte[] hexToBytes(String hex) {
            int len = hex.length();
            byte[] data = new byte[len / 2];
            for (int i = 0; i < len; i += 2) {
                data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                        + Character.digit(hex.charAt(i + 1), 16));
            }
            return data;
        }
    }

    // =========================================================================
    // FORMATTING UTILITIES
    // =========================================================================
    public static String formatSen(long sen) {
        return String.format("RM %.2f", sen / 100.0);
    }

    public static String formatTime(long millis) {
        return Instant.ofEpochMilli(millis).atZone(KL_ZONE).format(DT_FORMAT);
    }

    // =========================================================================
    // APPLICATION ENTRY & MENUS
    // =========================================================================
    public static void main(String[] args) {
        while (true) {
            System.out.println("\n========================================");
            System.out.println("     FLEXI PARKING SYSTEM - WELCOME");
            System.out.println("========================================");
            System.out.println("1. Register Account");
            System.out.println("2. Login");
            System.out.println("3. Exit");
            System.out.print("Select option (1-3): ");

            String choice = SCANNER.nextLine().trim();
            switch (choice) {
                case "1":
                    handleRegister();
                    break;
                case "2":
                    handleLogin();
                    break;
                case "3":
                    System.out.println("Thank you for using Flexi Parking System. Goodbye!");
                    System.exit(0);
                default:
                    System.out.println("Invalid option. Please choose 1, 2, or 3.");
            }
        }
    }

    public static void handleRegister() {
        System.out.println("\n--- User Registration ---");
        System.out.print("Enter username (3–20 letters, digits, underscores): ");
        String username = SCANNER.nextLine().trim().toLowerCase();

        if (!username.matches("^[a-z0-9_]{3,20}$")) {
            System.out.println("Registration failed. Username must contain 3–20 letters, digits, or underscores.");
            return;
        }

        Data data = Store.loadData();
        for (User u : data.users) {
            if (u.username.equals(username)) {
                System.out.println("Registration failed. Username already exists.");
                return;
            }
        }

        System.out.print("Enter password (8–128 characters): ");
        String password = SCANNER.nextLine().trim();

        if (password.length() < 8 || password.length() > 128) {
            System.out.println("Registration failed. Password must be between 8 and 128 characters.");
            return;
        }

        String saltHex = SecurityUtils.generateSaltHex();
        String hashHex = SecurityUtils.hashPassword(password, saltHex);

        // New accounts start with RM0.00 (0 sen)
        data.users.add(new User(username, saltHex, hashHex, 0L));

        if (Store.saveData(data)) {
            System.out.println("\n[Success] Account registered successfully!");
            System.out.println("Please log in using your new credentials.");
        }
    }

    public static void handleLogin() {
        System.out.println("\n--- User Login ---");
        System.out.print("Enter username: ");
        String username = SCANNER.nextLine().trim().toLowerCase();

        System.out.print("Enter password: ");
        String password = SCANNER.nextLine().trim();

        Data data = Store.loadData();
        User targetUser = null;
        for (User u : data.users) {
            if (u.username.equals(username)) {
                targetUser = u;
                break;
            }
        }

        if (targetUser == null || !SecurityUtils.verifyPassword(password, targetUser.saltHex, targetUser.hashHex)) {
            System.out.println("Login failed. Invalid username or password.");
            return;
        }

        System.out.println("\nLogin successful! Welcome back, " + targetUser.username + ".");
        userMenu(targetUser.username);
    }

    public static void userMenu(String username) {
        while (true) {
            Data data = Store.loadData();
            User currentUserObj = null;
            for (User u : data.users) {
                if (u.username.equals(username)) {
                    currentUserObj = u;
                    break;
                }
            }
            if (currentUserObj == null) {
                System.out.println("[Error] Account no longer exists.");
                return;
            }

            System.out.println("\n========================================");
            System.out.println("  FLEXI PARKING SYSTEM - USER MENU");
            System.out.println("========================================");
            System.out.println("User: " + currentUserObj.username + " | Balance: " + formatSen(currentUserObj.balanceSen));
            System.out.println("----------------------------------------");
            System.out.println("1. Manage Vehicles");
            System.out.println("2. Reload Wallet");
            System.out.println("3. Park Vehicle");
            System.out.println("4. View Parking Sessions");
            System.out.println("5. Extend Parking Session");
            System.out.println("6. Payment History & Receipts");
            System.out.println("7. Logout");
            System.out.println("8. Exit Program");
            System.out.print("Select option (1-8): ");

            String choice = SCANNER.nextLine().trim();
            switch (choice) {
                case "1":
                    handleVehicles(currentUserObj.username);
                    break;
                case "2":
                    handleReload(currentUserObj.username);
                    break;
                case "3":
                    handlePark(currentUserObj.username);
                    break;
                case "4":
                    handleViewSessions(currentUserObj.username);
                    break;
                case "5":
                    handleExtend(currentUserObj.username);
                    break;
                case "6":
                    handleHistory(currentUserObj.username);
                    break;
                case "7":
                    System.out.println("Logged out successfully.");
                    return;
                case "8":
                    System.out.println("Exiting application. Goodbye!");
                    System.exit(0);
                default:
                    System.out.println("Invalid option. Please choose between 1 and 8.");
            }
        }
    }

    // =========================================================================
    // SYSTEM FUNCTIONALITIES (1 to 10)
    // =========================================================================

    // 1 & 2. Vehicle Registration & Selection
    public static void handleVehicles(String username) {
        while (true) {
            Data data = Store.loadData();
            System.out.println("\n--- Vehicle Management ---");
            System.out.println("1. Register New Vehicle");
            System.out.println("2. View My Vehicles");
            System.out.println("3. Back to Main Menu");
            System.out.print("Select option (1-3): ");
            String choice = SCANNER.nextLine().trim();
            if (choice.equals("1")) {
                System.out.print("Enter number plate (2–12 letters or digits, spaces removed automatically): ");
                String plate = SCANNER.nextLine().trim().toUpperCase().replaceAll("\\s+", "");
                if (!plate.matches("^[A-Z0-9]{2,12}$")) {
                    System.out.println("Error: Invalid number plate. Must be 2–12 alphanumeric characters.");
                    continue;
                }
                boolean exists = false;
                for (Vehicle v : data.vehicles) {
                    if (v.plate.equals(plate)) {
                        exists = true;
                        break;
                    }
                }
                if (exists) {
                    System.out.println("Error: Number plate '" + plate + "' is already registered to an account.");
                    continue;
                }
                data.vehicles.add(new Vehicle(plate, username));
                if (Store.saveData(data)) {
                    System.out.println("[Success] Vehicle " + plate + " registered successfully.");
                }
            } else if (choice.equals("2")) {
                System.out.println("\n--- Your Registered Vehicles ---");
                boolean found = false;
                for (Vehicle v : data.vehicles) {
                    if (v.username.equals(username)) {
                        found = true;
                        System.out.println("- " + v.plate);
                    }
                }
                if (!found) {
                    System.out.println("You have no registered vehicles.");
                }
            } else if (choice.equals("3")) {
                break;
            } else {
                System.out.println("Invalid option.");
            }
        }
    }

    // 6. Prepaid Wallet Balance Checking & Simulated Reload
    public static void handleReload(String username) {
        System.out.println("\n--- Prepaid Wallet Reload ---");
        System.out.print("Enter reload amount in RM (positive, up to 2 decimal places): ");
        String input = SCANNER.nextLine().trim();
        long addSen;
        try {
            double val = Double.parseDouble(input);
            if (val <= 0) {
                System.out.println("Error: Reload amount must be positive.");
                return;
            }
            addSen = Math.round(val * 100.0);
        } catch (NumberFormatException e) {
            System.out.println("Error: Invalid monetary amount format.");
            return;
        }

        Data data = Store.loadData();
        User currentUser = null;
        for (User u : data.users) {
            if (u.username.equals(username)) {
                currentUser = u;
                break;
            }
        }

        if (currentUser == null) return;

        if (currentUser.balanceSen + addSen > 1000000L) {
            System.out.println("Error: Reload failed. Maximum wallet balance limit is RM10,000.00.");
            return;
        }

        currentUser.balanceSen += addSen;
        if (Store.saveData(data)) {
            System.out.println("[Success] Reload successful!");
            System.out.println("New Wallet Balance: " + formatSen(currentUser.balanceSen));
        }
    }

    // 3, 4, 5, 7, 8. Parking Location, Duration, Fee Calculation, Payment & Activation
    public static void handlePark(String username) {
        Data data = Store.loadData();
        List<Vehicle> myVehicles = new ArrayList<>();
        for (Vehicle v : data.vehicles) {
            if (v.username.equals(username)) {
                myVehicles.add(v);
            }
        }

        if (myVehicles.isEmpty()) {
            System.out.println("Error: You have no registered vehicles. Please register a vehicle first.");
            return;
        }

        System.out.println("\n--- Select Vehicle for Parking ---");
        for (int i = 0; i < myVehicles.size(); i++) {
            System.out.println((i + 1) + ". " + myVehicles.get(i).plate);
        }
        System.out.print("Select vehicle number: ");
        int vChoice;
        try {
            vChoice = Integer.parseInt(SCANNER.nextLine().trim());
            if (vChoice < 1 || vChoice > myVehicles.size()) {
                System.out.println("Invalid vehicle selection.");
                return;
            }
        } catch (NumberFormatException e) {
            System.out.println("Invalid input.");
            return;
        }
        String selectedPlate = myVehicles.get(vChoice - 1).plate;

        // Check if vehicle already has an active session
        long now = System.currentTimeMillis();
        for (ParkingSession s : data.sessions) {
            if (s.plate.equals(selectedPlate) && s.expiryTimeMillis > now) {
                System.out.println("Error: Vehicle " + selectedPlate + " already has an active parking session.");
                return;
            }
        }

        System.out.println("\n--- Select Parking Location ---");
        System.out.println("1. Kajang Sample A (RM0.60 per hour)");
        System.out.println("2. Kajang Sample B (RM1.20 per hour)");
        System.out.print("Select location (1-2): ");
        String locChoice = SCANNER.nextLine().trim();
        String locationName;
        long ratePerHourSen;
        if (locChoice.equals("1")) {
            locationName = "Kajang Sample A";
            ratePerHourSen = 60;
        } else if (locChoice.equals("2")) {
            locationName = "Kajang Sample B";
            ratePerHourSen = 120;
        } else {
            System.out.println("Invalid location selection.");
            return;
        }

        System.out.print("Enter parking duration in minutes (30 to 480, multiples of 30): ");
        int duration;
        try {
            duration = Integer.parseInt(SCANNER.nextLine().trim());
            if (duration < 30 || duration > 480 || duration % 30 != 0) {
                System.out.println("Error: Duration must be between 30 and 480 minutes in multiples of 30.");
                return;
            }
        } catch (NumberFormatException e) {
            System.out.println("Invalid input.");
            return;
        }

        // Fee calculation: hourly rate in sen * minutes / 60
        long feeSen = ratePerHourSen * duration / 60;

        System.out.println("\n--- Parking Fee Summary ---");
        System.out.println("Vehicle  : " + selectedPlate);
        System.out.println("Location : " + locationName);
        System.out.println("Duration : " + duration + " minutes");
        System.out.println("Total Fee: " + formatSen(feeSen));

        System.out.print("Confirm payment? (Enter 'Y' or 'y' to confirm, any other key to cancel): ");
        String confirm = SCANNER.nextLine().trim();
        if (!confirm.equalsIgnoreCase("Y")) {
            System.out.println("Parking payment cancelled. No changes saved.");
            return;
        }

        // Load fresh snapshot for atomic transaction check
        data = Store.loadData();
        User currentUser = null;
        for (User u : data.users) {
            if (u.username.equals(username)) {
                currentUser = u;
                break;
            }
        }

        if (currentUser.balanceSen < feeSen) {
            System.out.println("Error: Insufficient balance. Current balance: " + formatSen(currentUser.balanceSen) +
                    ", Required: " + formatSen(feeSen));
            return;
        }

        // Re-verify active session status on fresh snapshot
        for (ParkingSession s : data.sessions) {
            if (s.plate.equals(selectedPlate) && s.expiryTimeMillis > System.currentTimeMillis()) {
                System.out.println("Error: Vehicle " + selectedPlate + " already has an active parking session.");
                return;
            }
        }

        // Deduct balance and create session & receipt
        currentUser.balanceSen -= feeSen;
        long startTime = System.currentTimeMillis();
        long expiryTime = startTime + (duration * 60L * 1000L);
        String sessionId = "SESS-" + startTime + "-" + Math.abs(new Random().nextInt(900) + 100);
        String receiptId = "RCPT-P-" + startTime + "-" + Math.abs(new Random().nextInt(900) + 100);

        ParkingSession newSession = new ParkingSession(sessionId, username, selectedPlate, locationName, startTime, expiryTime, duration);
        Receipt newReceipt = new Receipt(receiptId, username, "PARK", feeSen, sessionId, startTime, expiryTime);

        data.sessions.add(newSession);
        data.receipts.add(newReceipt);

        if (Store.saveData(data)) {
            System.out.println("\n[Success] Parking session activated successfully!");
            System.out.println("Receipt ID   : " + receiptId);
            System.out.println("Session ID   : " + sessionId);
            System.out.println("Starting Time: " + formatTime(startTime));
            System.out.println("Expiry Time  : " + formatTime(expiryTime));
            System.out.println("Balance Left : " + formatSen(currentUser.balanceSen));
        }
    }

    // 4. View Active & Expired Sessions
    public static void handleViewSessions(String username) {
        Data data = Store.loadData();
        long now = System.currentTimeMillis();
        System.out.println("\n========================================");
        System.out.println("        YOUR PARKING SESSIONS");
        System.out.println("========================================");
        boolean found = false;
        for (ParkingSession s : data.sessions) {
            if (s.username.equals(username)) {
                found = true;
                boolean active = s.expiryTimeMillis > now;
                System.out.println("Session ID    : " + s.sessionId);
                System.out.println("Vehicle Plate : " + s.plate);
                System.out.println("Location      : " + s.location);
                System.out.println("Status        : " + (active ? "ACTIVE" : "EXPIRED"));
                System.out.println("Start Time    : " + formatTime(s.startTimeMillis));
                System.out.println("Expiry Time   : " + formatTime(s.expiryTimeMillis));
                System.out.println("Total Duration: " + s.totalDurationMinutes + " minutes");
                System.out.println("----------------------------------------");
            }
        }
        if (!found) {
            System.out.println("No parking sessions found.");
        }
    }

    // 9. Extension of an Active Parking Session
    public static void handleExtend(String username) {
        Data data = Store.loadData();
        long now = System.currentTimeMillis();
        List<ParkingSession> myActiveSessions = new ArrayList<>();
        for (ParkingSession s : data.sessions) {
            if (s.username.equals(username) && s.expiryTimeMillis > now) {
                myActiveSessions.add(s);
            }
        }

        if (myActiveSessions.isEmpty()) {
            System.out.println("Error: You have no active parking sessions to extend.");
            return;
        }

        System.out.println("\n--- Your Active Sessions ---");
        for (int i = 0; i < myActiveSessions.size(); i++) {
            ParkingSession s = myActiveSessions.get(i);
            System.out.println((i + 1) + ". Session ID: " + s.sessionId + " | Vehicle: " + s.plate +
                    " | Location: " + s.location + " | Expires: " + formatTime(s.expiryTimeMillis) +
                    " | Total Duration: " + s.totalDurationMinutes + " mins");
        }
        System.out.print("Select session number to extend: ");
        int sChoice;
        try {
            sChoice = Integer.parseInt(SCANNER.nextLine().trim());
            if (sChoice < 1 || sChoice > myActiveSessions.size()) {
                System.out.println("Invalid selection.");
                return;
            }
        } catch (NumberFormatException e) {
            System.out.println("Invalid input.");
            return;
        }

        ParkingSession selectedSession = myActiveSessions.get(sChoice - 1);

        System.out.print("Enter extension duration in minutes (30 to 480, multiples of 30): ");
        int extraMinutes;
        try {
            extraMinutes = Integer.parseInt(SCANNER.nextLine().trim());
            if (extraMinutes < 30 || extraMinutes > 480 || extraMinutes % 30 != 0) {
                System.out.println("Error: Extension duration must be between 30 and 480 minutes in multiples of 30.");
                return;
            }
        } catch (NumberFormatException e) {
            System.out.println("Invalid input.");
            return;
        }

        if (selectedSession.totalDurationMinutes + extraMinutes > 480) {
            System.out.println("Error: Total parking duration cannot exceed 480 minutes (Current: " +
                    selectedSession.totalDurationMinutes + " mins, Requested addition: " + extraMinutes + " mins).");
            return;
        }

        long ratePerHourSen = selectedSession.location.equals("Kajang Sample A") ? 60 : 120;
        long feeSen = ratePerHourSen * extraMinutes / 60;

        System.out.println("\n--- Extension Fee Summary ---");
        System.out.println("Session ID        : " + selectedSession.sessionId);
        System.out.println("Vehicle           : " + selectedSession.plate);
        System.out.println("Extension Duration: " + extraMinutes + " minutes");
        System.out.println("Extension Fee     : " + formatSen(feeSen));

        System.out.print("Confirm extension payment? (Enter 'Y' or 'y' to confirm, any other key to cancel): ");
        String confirm = SCANNER.nextLine().trim();
        if (!confirm.equalsIgnoreCase("Y")) {
            System.out.println("Extension cancelled. No changes saved.");
            return;
        }

        // Load fresh snapshot for transaction
        data = Store.loadData();
        User currentUser = null;
        for (User u : data.users) {
            if (u.username.equals(username)) {
                currentUser = u;
                break;
            }
        }

        if (currentUser.balanceSen < feeSen) {
            System.out.println("Error: Insufficient balance. Current balance: " + formatSen(currentUser.balanceSen));
            return;
        }

        ParkingSession targetSession = null;
        for (ParkingSession s : data.sessions) {
            if (s.sessionId.equals(selectedSession.sessionId)) {
                targetSession = s;
                break;
            }
        }

        if (targetSession == null || targetSession.expiryTimeMillis <= System.currentTimeMillis()) {
            System.out.println("Error: Session is no longer active.");
            return;
        }

        currentUser.balanceSen -= feeSen;
        long paymentTime = System.currentTimeMillis();
        long newExpiryTime = targetSession.expiryTimeMillis + (extraMinutes * 60L * 1000L);
        targetSession.expiryTimeMillis = newExpiryTime;
        targetSession.totalDurationMinutes += extraMinutes;

        String receiptId = "RCPT-E-" + paymentTime + "-" + Math.abs(new Random().nextInt(900) + 100);
        Receipt newReceipt = new Receipt(receiptId, username, "EXTEND", feeSen, targetSession.sessionId, paymentTime, newExpiryTime);
        data.receipts.add(newReceipt);

        if (Store.saveData(data)) {
            System.out.println("\n[Success] Session extended successfully!");
            System.out.println("Receipt ID   : " + receiptId);
            System.out.println("New Expiry   : " + formatTime(newExpiryTime));
            System.out.println("Total Duration: " + targetSession.totalDurationMinutes + " minutes");
            System.out.println("Balance Left : " + formatSen(currentUser.balanceSen));
        }
    }

    // 10. Parking Payment History and Receipts (Excludes reloads)
    public static void handleHistory(String username) {
        Data data = Store.loadData();
        System.out.println("\n========================================");
        System.out.println("      PARKING PAYMENT HISTORY & RECEIPTS");
        System.out.println("========================================");
        boolean found = false;
        for (Receipt r : data.receipts) {
            if (r.username.equals(username)) {
                found = true;
                System.out.println("Receipt ID    : " + r.receiptId);
                System.out.println("Payment Type  : " + r.type + (r.type.equals("PARK") ? " (Initial Parking)" : " (Session Extension)"));
                System.out.println("Amount Paid   : " + formatSen(r.amountSen));
                System.out.println("Session ID    : " + r.sessionId);
                System.out.println("Payment Time  : " + formatTime(r.paymentTimeMillis));
                System.out.println("Expiry Time   : " + formatTime(r.expiryTimeMillis));
                System.out.println("----------------------------------------");
            }
        }
        if (!found) {
            System.out.println("No parking payment history found.");
        }
    }
}
