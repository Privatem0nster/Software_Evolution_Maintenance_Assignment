import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.*;
import java.security.spec.*;
import java.time.*;
import java.time.format.DateTimeFormatter;
import java.util.*;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

public class ParkingAR {
    static final String DATA_FILE = "flexi_data.tsv";
    static final DateTimeFormatter DT_FMT = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss").withZone(ZoneId.of("Asia/Kuala_Lumpur"));
    static final int PBKDF2_ITER = 120000;
    static final int SALT_LEN = 16;
    static final int HASH_LEN = 32;
    static final long MAX_WALLET_SEN = 1000000L; // RM10,000

    // ---------- Data records ----------
    static class User {
        String username; String saltHex; String hashHex; long balanceSen;
        User() {}
        User(String u, String s, String h, long b) { username=u; saltHex=s; hashHex=h; balanceSen=b; }
    }
    static class Session {
        String id; String plate; String location; long startMs; long expiryMs; int totalMinutes; String username;
        Session() {}
        Session(String id, String plate, String loc, long st, long ex, int mins, String user) {
            this.id=id; this.plate=plate; this.location=loc; this.startMs=st; this.expiryMs=ex; this.totalMinutes=mins; this.username=user;
        }
    }
    static class Receipt {
        String id; String type; long amountSen; String sessionId; long payMs; long expiryMs; String username;
        Receipt() {}
        Receipt(String id, String type, long amt, String sid, long pay, long exp, String user) {
            this.id=id; this.type=type; this.amountSen=amt; this.sessionId=sid; this.payMs=pay; this.expiryMs=exp; this.username=user;
        }
    }

    // ---------- Data container ----------
    static class Data {
        Map<String,User> users = new LinkedHashMap<>();
        Map<String,String> vehicles = new LinkedHashMap<>(); // plate -> username
        List<Session> sessions = new ArrayList<>();
        List<Receipt> receipts = new ArrayList<>();
    }

    // ---------- Store ----------
    static class Store {
        static Data load() {
            Data d = new Data();
            Path p = Paths.get(DATA_FILE);
            if (!Files.exists(p)) return d;
            try {
                List<String> lines = Files.readAllLines(p, StandardCharsets.UTF_8);
                for (String line : lines) {
                    if (line.isEmpty()) continue;
                    String[] f = line.split("\t", -1);
                    if (f.length == 0) continue;
                    switch (f[0]) {
                        case "USER":
                            if (f.length >= 5) {
                                d.users.put(f[1], new User(f[1], f[2], f[3], Long.parseLong(f[4])));
                            }
                            break;
                        case "VEHICLE":
                            if (f.length >= 3) d.vehicles.put(f[1], f[2]);
                            break;
                        case "SESSION":
                            if (f.length >= 8) {
                                d.sessions.add(new Session(f[1], f[2], f[3], Long.parseLong(f[4]), Long.parseLong(f[5]), Integer.parseInt(f[6]), f[7]));
                            }
                            break;
                        case "RECEIPT":
                            if (f.length >= 8) {
                                d.receipts.add(new Receipt(f[1], f[2], Long.parseLong(f[3]), f[4], Long.parseLong(f[5]), Long.parseLong(f[6]), f[7]));
                            }
                            break;
                    }
                }
            } catch (Exception e) {
                System.err.println("Storage load error: " + e.getMessage());
                System.exit(1);
            }
            return d;
        }

        static boolean save(Data d) {
            Path p = Paths.get(DATA_FILE);
            Path tmp = Paths.get(DATA_FILE + ".tmp");
            try {
                StringBuilder sb = new StringBuilder();
                for (User u : d.users.values()) {
                    sb.append("USER\t").append(u.username).append("\t").append(u.saltHex).append("\t").append(u.hashHex).append("\t").append(u.balanceSen).append("\n");
                }
                for (Map.Entry<String,String> e : d.vehicles.entrySet()) {
                    sb.append("VEHICLE\t").append(e.getKey()).append("\t").append(e.getValue()).append("\n");
                }
                for (Session s : d.sessions) {
                    sb.append("SESSION\t").append(s.id).append("\t").append(s.plate).append("\t").append(s.location).append("\t")
                      .append(s.startMs).append("\t").append(s.expiryMs).append("\t").append(s.totalMinutes).append("\t").append(s.username).append("\n");
                }
                for (Receipt r : d.receipts) {
                    sb.append("RECEIPT\t").append(r.id).append("\t").append(r.type).append("\t").append(r.amountSen).append("\t")
                      .append(r.sessionId).append("\t").append(r.payMs).append("\t").append(r.expiryMs).append("\t").append(r.username).append("\n");
                }
                Files.write(tmp, sb.toString().getBytes(StandardCharsets.UTF_8));
                try {
                    Files.move(tmp, p, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
                } catch (AtomicMoveNotSupportedException e) {
                    Files.move(tmp, p, StandardCopyOption.REPLACE_EXISTING);
                }
                return true;
            } catch (Exception e) {
                System.err.println("Storage save error: " + e.getMessage());
                try { Files.deleteIfExists(tmp); } catch (Exception ignored) {}
                return false;
            }
        }
    }


    record Location(String name, long rate) {}
    static class AccountService {
        static boolean validUsername(String value) { return value.matches("[A-Za-z0-9_]{3,20}"); }
        static boolean validPlate(String value) { return value.matches("[A-Z0-9]{2,12}"); }
        static boolean validPassword(String value) { return value.length() >= 8 && value.length() <= 128; }
        static void register(Data d, String username, String password) {
            byte[] salt = Security.randomSalt();
            byte[] hash = Security.pbkdf2(password.toCharArray(), salt, PBKDF2_ITER, HASH_LEN);
            d.users.put(username, new User(username, Security.bytesToHex(salt), Security.bytesToHex(hash), 0L));
        }
        static boolean authenticate(User user, String password) {
            byte[] hash = Security.pbkdf2(password.toCharArray(), Security.hexToBytes(user.saltHex), PBKDF2_ITER, HASH_LEN);
            return Security.bytesToHex(hash).equals(user.hashHex);
        }
        static void addVehicle(Data d, String plate, String username) { d.vehicles.put(plate, username); }
    }
    static class PaymentService {
        static boolean withinLimit(User user, long amount) { return user.balanceSen + amount <= MAX_WALLET_SEN; }
        static boolean canPay(User user, long fee) { return user.balanceSen >= fee; }
        static void debit(User user, long fee) {
            if (!canPay(user, fee)) throw new IllegalArgumentException("Insufficient balance.");
            user.balanceSen -= fee;
        }
        static void credit(User user, long amount) { user.balanceSen += amount; }
    }
    static class ParkingService {
        static boolean hasActiveSession(Data d, String plate) {
            return d.sessions.stream().anyMatch(session -> session.plate.equals(plate) && session.expiryMs > System.currentTimeMillis());
        }
        static boolean canExtend(Session session, int extra) { return session.totalMinutes + extra <= 480; }
        static boolean validDuration(int minutes) { return minutes >= 30 && minutes <= 480 && minutes % 30 == 0; }
        static long fee(long rate, int minutes) { return rate * minutes / 60; }
        static long rate(String location) {
            if (location.equals("Kajang Sample A")) return 60;
            if (location.equals("Kajang Sample B")) return 120;
            throw new IllegalArgumentException("Unknown location.");
        }
        static Receipt charge(Data d, User user, Session session, String kind, long fee, long time) {
            PaymentService.debit(user, fee);
            Receipt receipt = new Receipt(Formatting.genId("R"), kind, fee, session.id, time, session.expiryMs, user.username);
            d.receipts.add(receipt);
            return receipt;
        }
        static Session activate(Data d, String username, String plate, String location, int minutes, long fee) {
            long now = System.currentTimeMillis();
            Session session = new Session(Formatting.genId("S"), plate, location, now, now + minutes * 60000L, minutes, username);
            charge(d, d.users.get(username), session, "PARK", fee, now);
            d.sessions.add(session);
            return session;
        }
        static Receipt extend(Data d, User user, Session session, int extra, long fee, long now) {
            session.expiryMs += extra * 60000L;
            session.totalMinutes += extra;
            return charge(d, user, session, "EXTEND", fee, now);
        }
    }
    static class Security {
    static String bytesToHex(byte[] b) {
        StringBuilder sb = new StringBuilder();
        for (byte x : b) sb.append(String.format("%02x", x));
        return sb.toString();
    }
    static byte[] hexToBytes(String s) {
        byte[] out = new byte[s.length()/2];
        for (int i=0;i<out.length;i++) out[i] = (byte)Integer.parseInt(s.substring(i*2,i*2+2),16);
        return out;
    }
    static byte[] randomSalt() {
        byte[] s = new byte[SALT_LEN];
        new SecureRandom().nextBytes(s);
        return s;
    }
    static byte[] pbkdf2(char[] password, byte[] salt, int iter, int len) {
        try {
            PBEKeySpec spec = new PBEKeySpec(password, salt, iter, len*8);
            SecretKeyFactory f = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            return f.generateSecret(spec).getEncoded();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
    }    static class Formatting {
    static long parseSen(String s) {
        try {
            double d = Double.parseDouble(s);
            if (d < 0) return -1;
            return Math.round(d * 100.0);
        } catch (Exception e) { return -1; }
    }
    static String senToRm(long sen) {
        return String.format("RM%.2f", sen / 100.0);
    }
    static String nowStr(long ms) { return DT_FMT.format(Instant.ofEpochMilli(ms)); }
    static String genId(String prefix) {
        return prefix + "-" + Long.toString(System.currentTimeMillis(), 36) + "-" + Integer.toString(new Random().nextInt(9999), 36);
    }


    }
    static class ConsoleUI {
    static Scanner sc = new Scanner(System.in);
    static String readLine(String prompt) {
        System.out.print(prompt);
        String s = sc.nextLine();
        return s == null ? "" : s.trim();
    }

    static void waitEnter() { readLine("Press Enter to continue..."); }

    static void run() {
        while (true) {
            System.out.println("\n=== Flexi Parking (A) ===");
            System.out.println("1. Register");
            System.out.println("2. Login");
            System.out.println("3. Exit");
            String c = readLine("Choose: ");
            if (c.equals("1")) doRegister();
            else if (c.equals("2")) doLogin();
            else if (c.equals("3")) { System.out.println("Bye."); return; }
            else System.out.println("Invalid choice.");
        }
    }

    static void doRegister() {
        Data d = Store.load();
        String uname = readLine("Username (3-20 letters/digits/_): ").toLowerCase();
        if (!AccountService.validUsername(uname)) { System.out.println("Invalid username."); return; }
        if (d.users.containsKey(uname)) { System.out.println("Username already taken."); return; }
        String pass = readLine("Password (8-128 chars): ");
        if (!AccountService.validPassword(pass)) { System.out.println("Invalid password length."); return; }
        AccountService.register(d, uname, pass);
        if (Store.save(d)) System.out.println("Registered. Please login.");
        else { System.out.println("Registration failed due to storage error."); }
    }

    static void doLogin() {
        Data d = Store.load();
        String uname = readLine("Username: ").toLowerCase();
        User u = d.users.get(uname);
        if (u == null) { System.out.println("Invalid username or password."); return; }
        String pass = readLine("Password: ");
        if (!AccountService.authenticate(u, pass)) { System.out.println("Invalid username or password."); return; }
        System.out.println("Welcome, " + u.username + "!");
        userMenu(u.username);
    }

    static void userMenu(String username) {
        while (true) {
            Data d = Store.load();
            User u = d.users.get(username);
            if (u == null) { System.out.println("Account not found."); return; }
            System.out.println("\n=== Menu (" + username + ") ===");
            System.out.println("Balance: " + Formatting.senToRm(u.balanceSen));
            System.out.println("1. Vehicles");
            System.out.println("2. Reload");
            System.out.println("3. Park");
            System.out.println("4. Sessions");
            System.out.println("5. Extend");
            System.out.println("6. History");
            System.out.println("7. Logout");
            System.out.println("8. Exit");
            String c = readLine("Choose: ");
            try {
                switch (c) {
                    case "1": vehicleMenu(username); break;
                    case "2": reload(username); break;
                    case "3": park(username); break;
                    case "4": showSessions(username); break;
                    case "5": extend(username); break;
                    case "6": showHistory(username); break;
                    case "7": return;
                    case "8": System.out.println("Bye."); System.exit(0);
                    default: System.out.println("Invalid choice.");
                }
            } catch (Exception e) {
                System.out.println("Error: " + e.getMessage());
            }
        }
    }

    static void vehicleMenu(String username) {
        while (true) {
            Data d = Store.load();
            System.out.println("\n--- Vehicles ---");
            List<String> mine = new ArrayList<>();
            for (Map.Entry<String,String> e : d.vehicles.entrySet())
                if (e.getValue().equals(username)) mine.add(e.getKey());
            if (mine.isEmpty()) System.out.println("(none)");
            else for (String p : mine) System.out.println("  " + p);
            System.out.println("1. Add vehicle");
            System.out.println("2. Back");
            String c = readLine("Choose: ");
            if (c.equals("2")) return;
            if (c.equals("1")) {
                String plate = readLine("Number plate: ").replaceAll("\\s+", "").toUpperCase();
                if (!AccountService.validPlate(plate)) { System.out.println("Invalid plate (2-12 letters/digits)."); continue; }
                if (d.vehicles.containsKey(plate)) { System.out.println("Plate already registered."); continue; }
                AccountService.addVehicle(d, plate, username);
                if (Store.save(d)) System.out.println("Vehicle added.");
                else System.out.println("Storage error; not saved.");
            }
        }
    }

    static void reload(String username) {
        Data d = Store.load();
        User u = d.users.get(username);
        String s = readLine("Reload amount RM (max 2 decimals): ");
        if (!s.matches("\\d+(\\.\\d{1,2})?")) { System.out.println("Invalid amount."); return; }
        long sen = Formatting.parseSen(s);
        if (sen <= 0) { System.out.println("Amount must be positive."); return; }
        if (!PaymentService.withinLimit(u, sen)) { System.out.println("Exceeds max balance RM10,000."); return; }
        PaymentService.credit(u, sen);
        if (Store.save(d)) System.out.println("Reloaded. New balance: " + Formatting.senToRm(u.balanceSen));
        else System.out.println("Storage error; reload not saved.");
    }

    static void park(String username) {
        Data d = Store.load();
        User u = d.users.get(username);
        String plate = selectOwnedVehicle(d, username);
        if (plate == null) return;
        if (ParkingService.hasActiveSession(d, plate)) {
            System.out.println("This vehicle already has an active session."); return;
        }

        Quote quote = readParkingQuote();
        if (quote == null) return;
        String loc = quote.location();
        int mins = quote.minutes();
        long feeSen = quote.fee();
        if (!confirmPayment()) return;

        if (!PaymentService.canPay(u, feeSen)) { System.out.println("Insufficient balance."); return; }

        Session activated = ParkingService.activate(d, username, plate, loc, mins, feeSen);
        saveParking(d, u, activated);
    }

    static void saveParking(Data d, User u, Session activated) {
        long now = activated.startMs;
        long expiry = activated.expiryMs;
        String sid = activated.id;
        String rid = d.receipts.get(d.receipts.size() - 1).id;
        if (Store.save(d)) {
            System.out.println("Parking activated. Session: " + sid);
            System.out.println("Receipt: " + rid + "  Start: " + Formatting.nowStr(now) + "  Expiry: " + Formatting.nowStr(expiry));
            System.out.println("New balance: " + Formatting.senToRm(u.balanceSen));
        } else {
            System.out.println("Storage error; parking not saved.");
        }
    }

    static void showSessions(String username) {
        Data d = Store.load();
        long now = System.currentTimeMillis();
        System.out.println("\n--- Active Sessions ---");
        boolean any = false;
        for (Session s : d.sessions) {
            if (s.username.equals(username) && s.expiryMs > now) {
                any = true;
                System.out.println(s.id + " | " + s.plate + " | " + s.location + " | start " + Formatting.nowStr(s.startMs) + " | expiry " + Formatting.nowStr(s.expiryMs) + " | " + s.totalMinutes + " min");
            }
        }
        if (!any) System.out.println("(none)");
        System.out.println("\n--- Expired Sessions ---");
        any = false;
        for (Session s : d.sessions) {
            if (s.username.equals(username) && s.expiryMs <= now) {
                any = true;
                System.out.println(s.id + " | " + s.plate + " | " + s.location + " | start " + Formatting.nowStr(s.startMs) + " | expiry " + Formatting.nowStr(s.expiryMs) + " | " + s.totalMinutes + " min");
            }
        }
        if (!any) System.out.println("(none)");
        waitEnter();
    }

    static void extend(String username) {
        Data d = Store.load();
        User u = d.users.get(username);
        long now = System.currentTimeMillis();
        Session s = selectActiveSession(d, username, now);
        if (s == null) return;
        long rateSen = ParkingService.rate(s.location);

        Integer extra = readDuration("Extra minutes (30-480, multiples of 30): ");
        if (extra == null) return;
        if (!ParkingService.canExtend(s, extra)) { System.out.println("Total duration would exceed 480 minutes."); return; }

        long feeSen = ParkingService.fee(rateSen, extra);
        System.out.println("Extension fee: " + Formatting.senToRm(feeSen));
        if (!confirmPayment()) return;

        if (!PaymentService.canPay(u, feeSen)) { System.out.println("Insufficient balance."); return; }

        Receipt receipt = ParkingService.extend(d, u, s, extra, feeSen, now);
        saveExtension(d, u, receipt);
    }

    static void saveExtension(Data d, User u, Receipt receipt) {
        long newExpiry = receipt.expiryMs;
        String rid = receipt.id;
        if (Store.save(d)) {
            System.out.println("Extended. Receipt: " + rid + "  New expiry: " + Formatting.nowStr(newExpiry));
            System.out.println("New balance: " + Formatting.senToRm(u.balanceSen));
        } else {
            System.out.println("Storage error; extension not saved.");
        }
    }

    static void showHistory(String username) {
        Data d = Store.load();
        System.out.println("\n--- Parking Payment History ---");
        List<Receipt> list = new ArrayList<>();
        for (Receipt r : d.receipts)
            if (r.username.equals(username) && (r.type.equals("PARK") || r.type.equals("EXTEND"))) list.add(r);
        list.sort(Comparator.comparingLong(r -> r.payMs));
        if (list.isEmpty()) { System.out.println("(none)"); waitEnter(); return; }
        System.out.printf("%-18s %-8s %-10s %-18s %-20s %-20s%n", "Receipt", "Type", "Amount", "Session", "Payment Time", "Expiry");
        for (Receipt r : list) {
            System.out.printf("%-18s %-8s %-10s %-18s %-20s %-20s%n",
                r.id, r.type, Formatting.senToRm(r.amountSen), r.sessionId, Formatting.nowStr(r.payMs), Formatting.nowStr(r.expiryMs));
        }
        waitEnter();
    }
    record Quote(String location, int minutes, long fee) {}
    static Quote readParkingQuote() {
        Location location = selectLocation();
        if (location == null) return null;
        String loc = location.name();
        long rateSen = location.rate();
        Integer mins = readDuration("Duration minutes (30-480, multiples of 30): ");
        if (mins == null) return null;

        long feeSen = ParkingService.fee(rateSen, mins); // integer sen
        System.out.println("Fee: " + Formatting.senToRm(feeSen));
        return new Quote(loc, mins, feeSen);
    }
    static String selectOwnedVehicle(Data d, String username) {
        List<String> mine = new ArrayList<>();
        for (Map.Entry<String,String> e : d.vehicles.entrySet())
            if (e.getValue().equals(username)) mine.add(e.getKey());
        if (mine.isEmpty()) { System.out.println("No vehicles. Add one first."); return null; }

        System.out.println("Your vehicles:");
        for (int i=0;i<mine.size();i++) System.out.println((i+1)+". "+mine.get(i));
        String ps = readLine("Select vehicle #: ");
        int pi;
        try { pi = Integer.parseInt(ps) - 1; } catch (Exception e) { System.out.println("Invalid."); return null; }
        if (pi < 0 || pi >= mine.size()) { System.out.println("Invalid."); return null; }
        String plate = mine.get(pi);

        return plate;
    }
    static Location selectLocation() {
        System.out.println("1. Kajang Sample A - RM0.60/hour");
        System.out.println("2. Kajang Sample B - RM1.20/hour");
        String ls = readLine("Select location: ");
        String loc; long rateSen;
        if (ls.equals("1")) { loc = "Kajang Sample A"; rateSen = ParkingService.rate("Kajang Sample A"); }
        else if (ls.equals("2")) { loc = "Kajang Sample B"; rateSen = ParkingService.rate("Kajang Sample B"); }
        else { System.out.println("Invalid location."); return null; }

        return new Location(loc, rateSen);
    }
    static Session selectActiveSession(Data d, String username, long now) {
        List<Session> active = new ArrayList<>();
        for (Session s : d.sessions)
            if (s.username.equals(username) && s.expiryMs > now) active.add(s);
        if (active.isEmpty()) { System.out.println("No active sessions."); return null; }

        System.out.println("Active sessions:");
        for (int i=0;i<active.size();i++) {
            Session s = active.get(i);
            System.out.println((i+1)+". "+s.id+" | "+s.plate+" | "+s.location+" | expiry "+Formatting.nowStr(s.expiryMs)+" | "+s.totalMinutes+" min");
        }
        String cs = readLine("Select session #: ");
        int ci;
        try { ci = Integer.parseInt(cs) - 1; } catch (Exception e) { System.out.println("Invalid."); return null; }
        if (ci < 0 || ci >= active.size()) { System.out.println("Invalid."); return null; }
        Session s = active.get(ci);

        return s;
    }
    static Integer readDuration(String prompt) {
        int minutes;
        try { minutes = Integer.parseInt(readLine(prompt)); }
        catch (Exception e) { System.out.println("Invalid."); return null; }
        if (!ParkingService.validDuration(minutes)) { System.out.println("Invalid duration."); return null; }
        return minutes;
    }
    static boolean confirmPayment() {
        if (readLine("Confirm payment? (Y/y to pay): ").equalsIgnoreCase("y")) return true;
        System.out.println("Cancelled.");
        return false;
    }
    }
    public static void main(String[] args) { ConsoleUI.run(); }
}
