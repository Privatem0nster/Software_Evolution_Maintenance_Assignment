import java.io.*;
import java.nio.file.*;
import java.security.*;
import java.time.*;
import java.util.*;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
 
public class ParkingB {
    // Shared data and rules are identical in all versions.
    record User(String salt, String hash, long balance) {}
    record Session(String owner, String plate, int zone, long start, long end) {}
    record Receipt(String owner, String session, String kind, long amount,
                   long time, long expiry) {}
    static class Data {
        Map<String, User> users = new LinkedHashMap<>();
        Map<String, String> vehicles = new LinkedHashMap<>();
        Map<String, Session> sessions = new LinkedHashMap<>();
        Map<String, Receipt> receipts = new LinkedHashMap<>();
    }
    static final String[] ZONES = {"Kajang Sample A", "Kajang Sample B"};
    static final long[] RATES = {60, 120}; // sen per hour; sample rates
    static final long MAX_BALANCE = 1000000; // RM10,000
    static final Scanner IN = new Scanner(System.in);
    static String ask(String label) {
        System.out.print(label + ": ");
        if (!IN.hasNextLine()) throw new NoSuchElementException();
        return IN.nextLine().trim();
    }
    static void require(boolean ok, String message) {
        if (!ok) throw new IllegalArgumentException(message);
    }
    static int number(String text) {
        try { return Integer.parseInt(text); }
        catch (NumberFormatException e) {
            throw new IllegalArgumentException("Enter a whole number.");
        }
    }
    static int minutes(String text) {
        int value = number(text);
        require(value >= 30 && value <= 480 && value % 30 == 0,
                "Duration must be 30 to 480 minutes in steps of 30.");
        return value;
    }
    static long money(String text) {
        require(text.matches("[0-9]{1,5}(\\.[0-9]{1,2})?"),
                "Use a positive RM amount with at most 2 decimal places.");
        long value = new java.math.BigDecimal(text).movePointRight(2).longValueExact();
        require(value > 0 && value <= MAX_BALANCE, "Reload must be RM0.01 to RM10,000.");
        return value;
    }
    static String rm(long sen) { return String.format(Locale.ROOT, "RM%d.%02d", sen / 100, sen % 100); }
    static String username(String text) {
        String name = text.toLowerCase(Locale.ROOT);
        require(name.matches("[a-z0-9_]{3,20}"), "Username: 3-20 letters, digits or underscore.");
        return name;
    }
    static String plate(String text) {
        String p = text.replace(" ", "").toUpperCase(Locale.ROOT);
        require(p.matches("[A-Z0-9]{2,12}"), "Plate: 2-12 letters or digits.");
        return p;
    }
    static String hash(String password, String salt) {
        try {
            PBEKeySpec spec = new PBEKeySpec(password.toCharArray(),
                    HexFormat.of().parseHex(salt), 120000, 256);
            byte[] result = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
                    .generateSecret(spec).getEncoded();
            spec.clearPassword();
            return HexFormat.of().formatHex(result);
        } catch (GeneralSecurityException e) { throw new IllegalStateException(e); }
    }
    static User newUser(String password) {
        require(password.length() >= 8 && password.length() <= 128,
                "Password: 8-128 characters.");
        byte[] bytes = new byte[16]; new SecureRandom().nextBytes(bytes);
        String salt = HexFormat.of().formatHex(bytes);
        return new User(salt, hash(password, salt), 0);
    }
    static long now() { return Clock.systemUTC().millis(); }
    static String id() { return UUID.randomUUID().toString(); }
    static String date(long time) {
        return Instant.ofEpochMilli(time).atZone(ZoneId.of("Asia/Kuala_Lumpur")).toString();
    }
    static String receipt(String id, Receipt r) {
        return "Receipt " + id + " | " + r.kind() + " | " + rm(r.amount())
                + " | Session " + r.session() + " | " + date(r.time())
                + " | Expiry " + date(r.expiry());
    }
    static class Store {
        final Path path;
        Store(String file) { path = Path.of(file).toAbsolutePath(); }
        Data load() throws IOException {
            Data d = new Data();
            if (!Files.exists(path)) return d;
            List<String> lines = Files.readAllLines(path);
            if (lines.isEmpty() || !lines.get(0).equals("FLEXI1"))
                throw new IOException("Invalid data file; restore a backup.");
            try {
                for (String line : lines.subList(1, lines.size())) {
                    String[] p = line.split("\\t", -1);
                    switch (p[0]) {
                        case "U" -> d.users.put(p[1], new User(p[2], p[3], Long.parseLong(p[4])));
                        case "V" -> d.vehicles.put(p[1], p[2]);
                        case "S" -> d.sessions.put(p[1], new Session(p[2], p[3],
                                Integer.parseInt(p[4]), Long.parseLong(p[5]), Long.parseLong(p[6])));
                        case "R" -> d.receipts.put(p[1], new Receipt(p[2], p[3], p[4],
                                Long.parseLong(p[5]), Long.parseLong(p[6]), Long.parseLong(p[7])));
                        default -> throw new IllegalArgumentException();
                    }
                }
            } catch (RuntimeException e) { throw new IOException("Invalid data file; restore a backup.", e); }
            return d;
        }
        void save(Data d) throws IOException {
            List<String> lines = new ArrayList<>(); lines.add("FLEXI1");
            d.users.forEach((k, u) -> lines.add(String.join("\t", "U", k, u.salt(), u.hash(), "" + u.balance())));
            d.vehicles.forEach((p, u) -> lines.add(String.join("\t", "V", p, u)));
            d.sessions.forEach((k, s) -> lines.add(String.join("\t", "S", k, s.owner(), s.plate(),
                    "" + s.zone(), "" + s.start(), "" + s.end())));
            d.receipts.forEach((k, r) -> lines.add(String.join("\t", "R", k, r.owner(), r.session(),
                    r.kind(), "" + r.amount(), "" + r.time(), "" + r.expiry())));
            Path temp = Files.createTempFile(path.getParent(), "flexi-", ".tmp");
            try {
                Files.write(temp, lines);
                Files.move(temp, path, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
            } finally { Files.deleteIfExists(temp); }
        }
    }
    static class Accounts {
        void register(Data d, String name, String password) {
            require(!d.users.containsKey(name), "Username already exists.");
            d.users.put(name, newUser(password));
        }
        void login(Data d, String name, String password) {
            User u = d.users.get(name);
            require(u != null && hash(password, u.salt()).equals(u.hash()), "Invalid credentials.");
        }
        void addVehicle(Data d, String owner, String p) {
            require(!d.vehicles.containsKey(p), "Plate already registered.");
            d.vehicles.put(p, owner);
        }
    }
    static class Payments {
        void reload(Data d, String owner, long amount) {
            User u = d.users.get(owner);
            require(amount > 0 && amount <= MAX_BALANCE, "Invalid reload.");
            require(u.balance() + amount <= MAX_BALANCE, "Wallet limit is RM10,000.");
            d.users.put(owner, new User(u.salt(), u.hash(), u.balance() + amount));
        }
        String charge(Data d, String owner, String sid, String kind,
                      long fee, long time, long expiry) {
            User u = d.users.get(owner);
            require(fee > 0, "Invalid payment.");
            require(u.balance() >= fee, "Insufficient balance.");
            String rid = id();
            d.users.put(owner, new User(u.salt(), u.hash(), u.balance() - fee));
            d.receipts.put(rid, new Receipt(owner, sid, kind, fee, time, expiry));
            return rid;
        }
    }
    static class Parking {
        final Payments payments;
        final Clock clock;
        Parking(Payments payments, Clock clock) { this.payments = payments; this.clock = clock; }
        long quote(int zone, int duration) {
            require(zone >= 0 && zone < ZONES.length, "Invalid zone.");
            minutes("" + duration);
            return RATES[zone] * duration / 60;
        }
        Session owned(Data d, String owner, String sid) {
            Session s = d.sessions.get(sid);
            require(s != null && s.owner().equals(owner), "Session not found.");
            return s;
        }
        String start(Data d, String owner, String p, int zone, int duration) {
            require(owner.equals(d.vehicles.get(p)), "Select your registered vehicle.");
            long fee = quote(zone, duration), time = clock.millis();
            for (Session s : d.sessions.values())
                require(!s.plate().equals(p) || s.end() <= time, "Vehicle already has active parking.");
            String sid = id();
            long end = time + duration * 60000L;
            String rid = payments.charge(d, owner, sid, "PARK", fee, time, end);
            d.sessions.put(sid, new Session(owner, p, zone, time, end));
            return rid;
        }
        String extend(Data d, String owner, String sid, int duration) {
            Session s = owned(d, owner, sid);
            long fee = quote(s.zone(), duration), time = clock.millis();
            long end = s.end() + duration * 60000L;
            require(end - s.start() <= 480 * 60000L, "Total session limit is 480 minutes.");
            require(s.end() > time, "Session expired; start new parking.");
            String rid = payments.charge(d, owner, sid, "EXTEND", fee, time, end);
            d.sessions.put(sid, new Session(owner, s.plate(), s.zone(), s.start(), end));
            return rid;
        }
    }
    static class ConsoleUI {
        final Store store;
        final Accounts accounts = new Accounts();
        final Payments payments = new Payments();
        final Parking parking = new Parking(payments, Clock.systemUTC());
        String current;
        ConsoleUI(Store store) { this.store = store; }
        void vehicles(Data d) {
            d.vehicles.forEach((p, owner) -> { if (owner.equals(current)) System.out.println(p); });
        }
        void sessions(Data d) {
            d.sessions.forEach((sid, s) -> {
                if (s.owner().equals(current)) System.out.println(sid + " | " + s.plate()
                        + " | " + ZONES[s.zone()] + " | " + date(s.start()) + " -> " + date(s.end())
                        + " | " + (s.end() > now() ? "ACTIVE" : "EXPIRED"));
            });
        }
        void history(Data d) {
            var list = d.receipts.entrySet().stream()
                    .filter(e -> e.getValue().owner().equals(current)).toList();
            if (list.isEmpty()) System.out.println("No payments yet.");
            list.forEach(e -> System.out.println(receipt(e.getKey(), e.getValue())));
        }
        void access(Data d, String choice) throws IOException {
            require(choice.equals("1") || choice.equals("2"), "Invalid option.");
            String name = username(ask("Username")), password = ask("Password");
            if (choice.equals("1")) {
                accounts.register(d, name, password); store.save(d);
                System.out.println("Account saved. Please log in.");
            } else {
                accounts.login(d, name, password); current = name;
                System.out.println("Welcome " + current);
            }
        }
        void pay(Data d, boolean extending) throws IOException {
            String sid = null, p = null; int zone;
            if (extending) {
                sid = ask("Session ID (see Sessions)");
                zone = parking.owned(d, current, sid).zone();
            } else {
                vehicles(d); p = plate(ask("Select plate"));
                require(current.equals(d.vehicles.get(p)), "Select your registered vehicle.");
                for (int i = 0; i < ZONES.length; i++)
                    System.out.println((i + 1) + " " + ZONES[i] + " " + rm(RATES[i]) + "/hour");
                zone = number(ask("Zone")) - 1;
            }
            int duration = minutes(ask(extending ? "Extra minutes" : "Minutes (60 = 1 hour)"));
            System.out.println("Fee " + rm(parking.quote(zone, duration)));
            if (!ask("Pay? Y/N").equalsIgnoreCase("Y")) return;
            String rid = extending ? parking.extend(d, current, sid, duration)
                    : parking.start(d, current, p, zone, duration);
            store.save(d); System.out.println(receipt(rid, d.receipts.get(rid)));
        }
        void menu(Data d, String choice) throws IOException {
            switch (choice) {
                case "1" -> {
                    accounts.addVehicle(d, current, plate(ask("Plate"))); store.save(d);
                    System.out.println("Vehicle saved.");
                }
                case "2" -> vehicles(d);
                case "3" -> {
                    payments.reload(d, current, money(ask("Reload RM"))); store.save(d);
                    System.out.println("Reload saved.");
                }
                case "4" -> pay(d, false);
                case "5" -> sessions(d);
                case "6" -> pay(d, true);
                case "7" -> history(d);
                case "8" -> current = null;
                default -> throw new IllegalArgumentException("Invalid option.");
            }
        }
        void run() {
            while (true) {
                try {
                    Data d = store.load();
                    if (current == null) System.out.println("1 Register | 2 Login | 0 Exit");
                    else {
                        System.out.println("User " + current + " | Balance " + rm(d.users.get(current).balance()));
                        System.out.println("1 Add vehicle | 2 Vehicles | 3 Reload | 4 Park");
                        System.out.println("5 Sessions | 6 Extend | 7 History | 8 Logout | 0 Exit");
                    }
                    String choice = ask("Choice");
                    if (choice.equals("0")) return;
                    if (current == null) access(d, choice); else menu(d, choice);
                } catch (IllegalArgumentException e) { System.out.println("Error: " + e.getMessage()); }
                catch (IOException e) { System.out.println("Storage error; operation not confirmed: " + e.getMessage()); return; }
                catch (NoSuchElementException e) { return; }
            }
        }
    }
    public static void main(String[] args) {
        new ConsoleUI(new Store(args.length == 0 ? "parking-b.tsv" : args[0])).run();
    }
}

