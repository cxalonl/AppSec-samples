Java
Beginner

Challenge: SQLi, Broken Access Control and XSS

 

 
@RequestMapping("/login")
public String login(@RequestParam Map<String, String> parameters, HttpServletRequest request, HttpServletResponse response, Model model) {
    if (request.getMethod().equals("POST") && !parameters.isEmpty()) {
        String query = String.format("SELECT username, email, name FROM users WHERE username='%s' AND password='%s'", parameters.get("uname"), parameters.get("psw"));
        User user = jdbcTemplate.queryForObject(query, new UserRowMapper());
        if (user != null) {
            model.addAttribute("name", user.getName());
            model.addAttribute("email", user.getEmail());
            response.addCookie(new Cookie("logged_in", "true"));
            if (user.getUsername().equals("admin")) {
                response.addCookie(new Cookie("admin", "true"));
            }
            return "profile";
        }
    }
    return "login";
}

Mitigation:

    Use parameterized queries

    Don’t use access control logic in logic that can be manipulated by the user

@RequestMapping("/login")
public String login(@RequestParam Map<String, String> parameters, HttpServletRequest request, Model model) {
    if (request.getMethod().equals("POST") && !parameters.isEmpty()) {
        String query = "SELECT username, email, name FROM users WHERE username=? AND password=?";
        User user = jdbcTemplate.queryForObject(query, new UserRowMapper(), parameters.get("uname"), parameters.get("psw"));
        if (user != null) {
            model.addAttribute("name", user.getName());
            model.addAttribute("email", user.getEmail());
            request.getSession().setAttribute("logged_in", true);
            if (user.getUsername().equals("admin")) {
                request.getSession().setAttribute("admin", true);
            }
            return "profile";
        }
    }
    return "login";
}
Medium

Challenge: Deserialization and XSS(optional)

 

 
@GetMapping("/profile")
public String profile(Model model, @CookieValue(name = "user") String userCookie) {
    byte[] dataBytes = Base64.getDecoder().decode(userCookie);
    final ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(dataBytes);
    final ObjectInputStream objectInputStream = new ObjectInputStream(byteArrayInputStream);
    final User user = (User) objectInputStream.readObject();
    objectInputStream.close();
    model.addAttribute("name", user.getName());
    model.addAttribute("email", user.getEmail());
    return "profile";
}

Mitigation:

    Avoid using deserialization. 

 

Other mitigations: 

     

    Escape the input. XSS happens in some template engines and others already have capabilities to auto-escape the input.

@GetMapping("/profile")
public String profile(Model model, @CookieValue(name = "user") String userCookie) {
    byte[] dataBytes = Base64.getDecoder().decode(userCookie);
    final ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(dataBytes);
    final ValidatingObjectInputStream objectInputStream = new ValidatingObjectInputStream(byteArrayInputStream);
    objectInputStream.accept(User.class);
    final User user = (User) objectInputStream.readObject();
    objectInputStream.close();
    model.addAttribute("name", escape_XSS(user.getName()));
    model.addAttribute("email", escape_XSS(user.getEmail()));
    return "profile";
}
Hard

Challenge: SPEL, XXE and XSS(optional)

 

 
@GetMapping("/user")
public String userProfile(Model model, @RequestParam String name) {
    model.addAttribute("name", name);
    return "profiles/" + name + "/welcome";
}
    
@PostMapping("/upload_profile")
public String uploadProfile(@RequestParam("file") MultipartFile file) throws IOException, XMLStreamException {
    XMLInputFactory factory = XMLInputFactory.newFactory();
    XMLStreamReader reader = factory.createXMLStreamReader(file.getInputStream());
    String name = "";
    while(reader.hasNext()) {
        if (reader.next() == XMLStreamConstants.START_ELEMENT && reader.getLocalName().equals("name")) {
            name = reader.getElementText();
        }
    }
    return "redirect:/user?name=" + name;
}

Mitigation:

    Sanitize the input

    Disable external entities resolution and DTD

@GetMapping("/user")
public String userProfile(Model model, @RequestParam String name) {
    model.addAttribute("name", name);
    return "profiles/" + sanitizeInput(name) + "/welcome";
}
    
@PostMapping("/upload_profile")
public String uploadProfile(@RequestParam("file") MultipartFile file) throws IOException, XMLStreamException {
    XMLInputFactory factory = XMLInputFactory.newFactory();
    factory.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false);
    factory.setProperty(XMLInputFactory.SUPPORT_DTD, false);
    XMLStreamReader reader = factory.createXMLStreamReader(file.getInputStream());
    String name = "";
    while(reader.hasNext()) {
        if (reader.next() == XMLStreamConstants.START_ELEMENT && reader.getLocalName().equals("name")) {
            name = reader.getElementText();
        }
    }
    return "redirect:/user?name=" + name;
}
Insane

Challenge: Command Argument Injection, XSS, Comparison Timing Attack, Plaintext Storage of a Password, Information Exposure Through Logs (optional)

 

 

 

 

 
@Override
@PostMapping("/login")
public Authentication authenticate(HttpServletRequest request, Authentication authentication) throws AuthenticationException {
  
  	private PasswordEncoder encoder;

    String username = request.getParameter("username");
    String password = request.getParameter("password");

    User user = userRepo.findOne(username);
    if (user == null) {
        throw new BadCredentialsException("1000");
    }

    if (!encoder.encode(password).equals(user.getPassword())) {
        throw new BadCredentialsException("1000");
    }
    List<Right> userRights = rightRepo.getUserRights(username);

    return new UsernamePasswordAuthenticationToken(username, null,
                userRights.stream().map(x -> new SimpleGrantedAuthority(x.getName())).collect(Collectors.toList()));

}

@PostMapping("/ping")
public String pingHost(Model model, HttpServletRequest request) throws ServletException, IOException {

    String PING_COMMAND = "ping";
    String response = "";
    String host = request.getParameter("host").replaceAll("<.*?>", "");
    
    try {
        Runtime runtime = Runtime.getRuntime();
        Process subProc = runtime.exec(PING_COMMAND + " " + host);
        BufferedReader irProcOutput = new BufferedReader(new InputStreamReader(subProc.getInputStream()));
        String line = null;
        while ((line = irProcOutput.readLine()) != null)
            response += line;
      	model.addAttribute("response", response);
    } catch (Exception ex) {
        Logger.warn(ex);
    }
  	
  	model.addAttribute("host", host);
    
  	return "index";
}
Python
Beginner

Challenge: SQLi, Stored XSS, IDOR(optional), and SSTI

 

 

 

 
@app.route('/user/<path:user_id>')
def get_user(user_id):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute(f"SELECT name, email FROM users WHERE user_id = '{user_id}'")
    data = cursor.fetchone()
    return render_template_string(f'''<!doctype html>
      <title>User information</title>
      <h1>User</h1>
      <p>Name: {data[0]}</p>
      <p>Email: {data[1]}</p>
      </form>''')

Mitigation:

    Use parameterized queries

    Escape input or use the template engines auto escape features

from markupsafe import escape

@app.route('/user/<path:user_id>')
def get_user(user_id):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute(f"SELECT name, email FROM users WHERE user_id = ?", (user_id,))
    data = cursor.fetchone()
    return f'''<!doctype html>
      <title>User information</title>
      <h1>User</h1>
      <p>Name: {escape(data[0])}</p>
      <p>Email: {escape(data[1])}</p>
      </form>'''
Medium

Challenge: Code execution, Path traversal, Misconfiguration

https://cwe.mitre.org/data/definitions/22.html 

https://cwe.mitre.org/data/definitions/1327.html 

https://cwe.mitre.org/data/definitions/489.html 
app.config['FILES_FOLDER'] = '/app/public'

@app.route('/calc', methods=['POST'])
def calc():
    result = int(eval(request.json['expression']))
    return jsonify({'result': result})

@app.route('/public/<path:name>')
def send_public(name):
    return send_file(app.config['FILES_FOLDER'] + name, as_attachment=True)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8000, debug=True)

Mitigation:

    Whitelist eval input

    Sanitize the Path input or use the send_from_directory

    Turn off debug mode, avoid using the '0.0.0.0' configuration (in containers: 

     )

app.config['FILES_FOLDER'] = '/app/public'

@app.route('/calc', methods=['POST'])
def calc():
    expression = request.json['expression']
    if expression in wordlist:
      result = int(eval(expression))
      return jsonify({'result': result})
    return jsonify({'error': 'Not allowed'})

@app.route('/get_file/<path:name>')
def get_file(name):
    return send_from_directory(app.config['FILES_FOLDER'], name, as_attachment=True)
    # or
    filename = os.path.basename(name)
    return send_file(app.config['FILES_FOLDER'] + filename, as_attachment=True)

if __name__ == '__main__':
    #app.run(host='0.0.0.0', port=8000, debug=True)
    # The host part is optional, since inside a container the app will need to expose the 0.0.0.0, nonetheles the app should use a wsgi
    app.run(host='127.0.0.1', port=8000, debug=False)
Hard

Challenge: Unsafe Reflection, Open Redirect, SSRF, Insecure random and predictable seed

 

 

 

 

 
import random
import string

random.seed('Hx6GtX&z$BRVFLsLLisD%77A3fqTbk')
app = Flask(__name__)
app.config['SECRET_KEY'] = ''.join(random.choice(string.ascii_letters) for i in range(20))

@app.route('/router')
def router():
    route = globals()[request.args.get('dispatcher')]()
    result = getattr(route, request.args.get('caller'))(request.args.get('route'))
    return redirect(result)

Mitigation:

    Use secure PRNG without hardcoded seeds

    Whitelist reflection inputs

    Control the redirect or sanitize it 

     

import os

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(32)
allowed_objs = ['route']
allowed_methods = ['link']

@app.route('/router')
def router():
    dispatcher = request.args.get('dispatcher')
    if dispatcher in allowed_objs:
        route = globals()[dispatcher]()
        caller = request.args.get('caller')
        if caller in allowed_methods:
            result = getattr(route, caller)(request.args.get('route'))
            return redirect('/' + result)
Insane

Challenge: Empty Password in Connection String, Hardcoded Credentials, TOCTOU(?) Race Condition (mktemp), Privacy Violation, Log Forging, Missing Encryption of Sensitive Data

  (Not in the DMS description? also no query for python?)

 

 

 

 

 
import os
import tempfile
import base64

from flask import Flask, render_template, request
from flask_mysqldb import MySQL

app = Flask(__name__)

app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = ''
app.config['MYSQL_DB'] = 'app'

mysql = MySQL(app)

@app.route("/profile/avatar", methods = ["GET", "POST"])
def upload_file2():
    if request.method == "POST":
        file = request.files["file"]
        fn = tempfile.mktemp(dir="uploads/")
        file.save(fn)

        user = base64.b64decode(request.cookies.get("user")).decode("ascii").split(":")

        with app.app_context():
            cursor = mysql.connection.cursor()
            cursor.execute(''' INSERT INTO users_avatars VALUES(%s,%s,%s) ''', (user[0], user[1], fn))

            app.logger.info(f"Updated user with id:email - {user[0]}:{user[1]}. \nNew avatar at path: {fn}")
            return "Avatar updated successfully."

if __name__ == "__main__":
    app.run(host='127.0.0.1', port=8000, debug=False)
Go
Beginner

Challenge: SQLi , XSS and Error message exposure

 

 

 
func searchHandler(w http.ResponseWriter, r *http.Request) {
    if r.Method == "GET" {
        var tpl = template.Must(template.ParseFiles("templates/search.html"))
        tpl.Execute(w, nil)
        return
    } else if r.Method == "POST" {
        _ := r.ParseForm()
        db, err := sql.Open("sqlite3", "items.db")
        if err != nil {
            w.Write([]byte(err.Error()))
            return
        }
        row := db.QueryRow(fmt.Sprintf("SELECT id, name, price, category FROM items WHERE id=%s", id))
        queryResult := item{}
        row.Scan(&queryResult.Id, &queryResult.Name, &queryResult.Price, &queryResult.Category)
    
        w.Write([]byte(fmt.Sprintf("%s %s %s", queryResult.Name, queryResult.Price, queryResult.Category)))
        return
    }
        w.Write([]byte("Not Allowed!"))
}

Mitigation:

    Use parameterized queries

    Escape input, use the template engines auto escape features or use JSON

func searchHandler(w http.ResponseWriter, r *http.Request) {
    if r.Method == "GET" {
        var tpl = template.Must(template.ParseFiles("templates/search.html"))
        tpl.Execute(w, nil)
        return
    } else if r.Method == "POST" {
        _ := r.ParseForm()
        db, err := sql.Open("sqlite3", "items.db")
        if err != nil {
            fmt.Println([]byte(err.Error()))
            return
        }
        row := db.QueryRow("SELECT id, name, price, category FROM items WHERE id=?", id)
        queryResult := item{}
        row.Scan(&queryResult.Id, &queryResult.Name, &queryResult.Price, &queryResult.Category)
        jsonOut, _ := json.Marshal(queryResult)
        w.Header().Set("Content-Type", "application/json")
        w.Write(jsonOut)
        return
    }
        w.Write([]byte("Not Allowed!"))
}
Medium

Challenge: Command Injection and Buffer Overflow

 

 

 
func checkResponseHandler(w http.ResponseWriter, r *http.Request) {
    var hostname = r.URL.Query().Get("hostname")
    tmp := exec.Command("bash")
    tmpWriter, _ := tmp.StdinPipe()
    var stdout, stderr bytes.Buffer
    tmp.Stdout = &stdout
    tmp.Stderr = &stderr
    var tmpInput = fmt.Sprintf("/usr/bin/curl %s", hostname)
    tmpWriter.Write([]byte(tmpInput + "\n"))
    tmpWriter.Close()
    tmp.Run()
    fmt.Println(string(stderr.Bytes()))
    response := (*[8*100]bytes)unsafe.Pointer(&stdout.Bytes()[0])
    w.Write(response)
}

Mitigation:

    Escape the Command input 

     

    Avoid unsafe usage, in this case it is unnecessary. In cases that the unsafe is really necessary, the inputs size should always be validated against buffer sizes.

func checkResponseHandler(w http.ResponseWriter, r *http.Request) {
    var hostname = r.URL.Query().Get("hostname")
    cmd := exec.Command("bash")
    cmdWriter, _ := cmd.StdinPipe()
    var stdout, stderr bytes.Buffer
    cmd.Stdout = &stdout
    cmd.Stderr = &stderr
    var cmdInput = fmt.Sprintf("/usr/bin/curl %s", shellescape.Quote(hostname))
    cmdWriter.Write([]byte(cmdInput + "\n"))
    cmdWriter.Close()
    cmd.Run()
    fmt.Println(string(stderr.Bytes()))
    w.Write(stdout.Bytes())
}
Hard

Challenge: Race condition and Use of Broken or Risky Cryptographic Algorithm

 

 
var code int
func getCode(w http.ResponseWriter, r *http.Request){
    code, err := strconv.Atoi(r.URL.Query().Get("code"))
    if(err == nil){
        fmt.Fprintf(w,"Invalid Voucher Format")
    }
}

func checkCode(){
    if(checkValidCode(code)){
      	key, _ := rsa.GenerateKey(rand.Reader, 1024)
        codeHash := sha1.Sum([]byte(code))
        var opts rsa.PSSOptions
        opts.Hash = crypto.SHA1
        signature, _ := rsa.SignPSS(rand.Reader, key, crypto.SHA1, codeHash[:], &opts)
        giveVouchertoUser(code, signature)
    }
}

func redeemVoucher(w http.ResponseWriter, r *http.Request){
    go getCode(w , r)
    go checkCode()
}

Mitigation:

    Redesign the above code, to be thread safe (all functions could be executed in parallel without any interference with one another)

    Implement a mutex to control the variable code. Therefore, allowing one thread to access the variable and blocking access to all other threads

    Hash function: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-131Ar1.pdf#[{"num"%3A66%2C"gen"%3A0}%2C{"name"%3A"XYZ"}%2C70%2C720%2C0]

    Key Pair generation (“This standard specifies the use of a modulus whose bit length is an even integer and greater than or equal to 2048 bits”): https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-5-draft.pdf

Insane

Challenge: Overly Permissive CSP, E-Mail Content Forgery, SSL Verification Bypass, Improper Error Handling, Open Redirect

 

 

 

 

 
package main

import (
  "fmt"
  "net/smtp"
  "crypto/tls"
  "strings"
)

func sendWelcomeEmail(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Security-Policy", "default-src *")
	var to := req.Form.Get("email")
	var msg := "Welcome, " + req.Form.Get("first_name") + "!"

	_ := smtp.SendMail(
		HOSTNAME,
		authSMTPObject,
		NO_REPLY_ADDRESS,
		[]string{to},
		[]byte(msg),  
	)

	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	
    _, err := http.Get("https://domain.com/")
    if err != nil {
		fmt.Println(err)
    }
	
	var loc := req.Form.Get("loc")
	if !strings.Contains(loc, "http") {
		http.Redirect(w, req, loc, http.StatusSeeOther)
	}
	else {
		http.Redirect(w, req, "/profile", http.StatusSeeOther)
	} 
}
C
Beginner

Challenge: Buffer Overflow and String format

 

 
#include <stdio.h>
#include <stdlib.h>

struct student {
    char firstName[50];
    float marks;
} s[5];

int main(void) {
    printf("Enter student information:\n");
    // storing information
    printf("Enter first name: ");
    gets(s[0].firstName);
    printf("Enter marks: ");
    scanf("%f", &s[0].marks);
    // displaying information
    printf("Displaying Information:\n\n");
    printf("First name: ");
    printf(s[0].firstName);
    printf("Marks: ");
    printf("%.1f", s[0].marks);
    printf("\n");
}

Mitigation:
#include <stdio.h>
#include <stdlib.h>

struct student {
    char firstName[50];
    float marks;
} s[5];

int main(void) {
    printf("Enter information of students:\n");
    // storing information
    printf("Enter first name: ");
    scanf("%49s", s[0].firstName);
    printf("Enter marks: ");
    scanf("%f", &s[0].marks);
    printf("Displaying Information:\n\n");
    // displaying information
    printf("First name: ");
    printf("%s", s[0].firstName);
    printf(s[0].firstName);
    printf("Marks: %.1f", s[0].marks);
    printf("\n");
}
Medium

Challenge: Heap inspection and Off by One Null Terminator

 

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
 
int main(void) {
    char *username = (char *) malloc(sizeof(char) * 20);
    char *password = (char *) malloc(sizeof(char) * 15);
    puts("Insert username:");
    scanf("%20s", username);
    puts("Insert password:");
    scanf("%14s", password);
    free(username);
    free(password);
}

Mitigation:

    Clear memory after use

    Leave space for the NULL terminator that scanf adds

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
 
int main(void) {
    char *username = (char *) malloc(sizeof(char) * 20);
    char *password = (char *) malloc(sizeof(char) * 15);
    puts("Insert username:");
    scanf("%19s", username);
    puts("Insert password:");
    scanf("%14s", password);
    memset(username, 0, sizeof(*username));
    free(username);
    memset(password, 0, sizeof(*password));
    free(password);
}
Hard

Challenge: User after Free

 

 
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

typedef struct string {
    unsigned length;
    char *data;
} string;

int main() {
    struct string* s = malloc(sizeof(string));
    puts("Length:");
    scanf("%u", &s->length);
    s->data = malloc(s->length + 1);
    memset(s->data, 0, s->length + 1);
    puts("Data:");
    read(0, s->data, s->length);
    free(s->data);
    free(s);
    char *s2 = malloc(16);
    memset(s2, 0, 16);
    puts("More data:");
    read(0, s2, 15);
    puts(s->data);
    return 0;
}

Mitigation:

    Clear memory after use

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

typedef struct string {
    unsigned length;
    char *data;
} string;

int main() {
    struct string* s = malloc(sizeof(string));
    puts("Length:");
    scanf("%u", &s->length);
    s->data = malloc(s->length + 1);
    memset(s->data, 0, s->length + 1);
    puts("Data:");
    read(0, s->data, s->length);
    memset(s->data, 0, s->length + 1)
    free(s->data);
    memset(s, 0 , sizeof(*s))
    free(s);
    char *s2 = malloc(16);
    memset(s2, 0, 16);
    puts("More data:");
    read(0, s2, 15);
    puts(s->data);
    return 0;
}
Insane

Challenge: Process Control, Double Free, Uncontrolled Memory Allocation (no query for C/CPP?)

 

 

 
#include <windows.h>
#include <malloc.h>
#include <stdio.h>

#define TOTALBYTES    8192
#define BYTEINCREMENT 4096

int main(int argc, char ** argv) {
  
  DWORD BufferSize = TOTALBYTES;
  DWORD cbData;
  DWORD dwRet;
  
  char* lib = (char*) malloc( BufferSize );
  cbData = BufferSize;

  if (argv[1] != NULL) {

    dwRet = RegQueryValueEx(HKEY_CURRENT_USER, "APPHOME", NULL, NULL, (LPBYTE) lib, &cbData);

    while( dwRet == ERROR_MORE_DATA )
    {
        BufferSize += BYTEINCREMENT;
        lib = (char*) realloc( lib, BufferSize );
        cbData = BufferSize;
        dwRet = RegQueryValueEx(HKEY_CURRENT_USER, "APPHOME", NULL, NULL, (LPBYTE) lib, &cbData);
    }
    if (dwRet == ERROR_SUCCESS) {
      printf("\n\nFinal buffer size is %d\n", BufferSize);
      LoadLibrary(lib);
      free(lib);
    }
    else printf("\nRegQueryValueEx failed (%d)\n", dwRet);
    
    LogSystemInfo();
    SendDiagnostics();
    free(lib);
 
  }

  return 0;

}

 
Singular Challenges (Other Languages)

 
PHP
Medium

Challenge: XXE, Unsafe Reflection

 

 
<?php
  
(...)
  
$dom = new DOMDocument(); 
$xmlInput = $_POST["xmlInput"];
$dom->loadXML($xmlInput, LIBXML_NOENT);
$data = simplexml_import_dom($dom);

$module = $data->module;
$scope = $data->data;
$helpNumber = $data->helpNumber;

if (isset($module) && !($module == 'main') && !($module == '')) {
  	include_once(__DIR__ . "/../lib/modules.inc");
    if (isset($scope)) {
        $helpEntry = getHelp($module,$helpNumber,$scope);
    }
    else {
        $helpEntry = getHelp($module,$helpNumber);
    }
}

function getHelp($moduleName,$helpID,$modScope='') {
    $moduleObject = getModule($moduleName, $modScope);
}

function getModule($name, $modScope) {
    self::$cache[$name . ':' . $modScope] = new $name($modScope);
}

(...)

?>
PL/SQL
Medium

Challenge: Privilege Escalation, SSRF

 (?)

 
/*
    - Only admin user was granted privileges to execute remote requests
    - The code sample is only vulnerable to SSRF if the invoker is the user admin
    
    Arguments: 
    {parameter name} {IN (default) | OUT | IN OUT} {parameter datatype} {(Optional) DEFAULT value}
*/
CREATE OR REPLACE PROCEDURE show_todos(id VARCHAR2)
AUTHID CURRENT_USER
AS  
BEGIN
    FOR rec IN (SELECT title FROM todo WHERE todo_id=id ORDER BY title)
    LOOP
        DBMS_OUTPUT.put_line(rec.title);
    END LOOP;

    IF SYS_CONTEXT ('userenv', 'current_user') = 'admin'
    THEN
    DECLARE 
        stmt VARCHAR2(300) := 'SELECT link FROM users WHERE id=:1';  
        url VARCHAR2(300);
        req UTL_HTTP.REQ;
        resp UTL_HTTP.RESP;
    BEGIN 
        EXECUTE IMMEDIATE stmt INTO url USING id;
        req   := UTL_HTTP.BEGIN_REQUEST(url);
        resp  := UTL_HTTP.GET_RESPONSE(req);
        DBMS_OUTPUT.put_line(resp.status_code);

        LOOP
            UTL_HTTP.READ_LINE(resp, data);
            DBMS_OUTPUT.put_line(data);
        END LOOP;

        UTL_HTTP.END_RESPONSE(resp);
    END;
    END IF;
EXCEPTION
    WHEN OTHERS
    THEN
        DBMS_OUTPUT.PUT_LINE (SQLERRM);
END;
/
COBOL
Medium

Challenge: Path Traversal, Module Injection

 

 
       IDENTIFICATION DIVISION.
       PROGRAM-ID. FILE_PATH_MANIPULATION.
       
       ENVIRONMENT DIVISION.
          INPUT-OUTPUT SECTION.
             FILE-CONTROL.  
             SELECT STUDENT ASSIGN TO FILENAME
             ORGANIZATION IS LINE SEQUENTIAL.            
       
       DATA DIVISION.
          FILE SECTION.
          FD STUDENT.
          01 STUDENT-FILE.
             05 STUDENT-ID PIC 9(5).
             05 NAME PIC A(25).

          01 FILENAME PIC X(12).
       
          WORKING-STORAGE SECTION.
          01 WS-STUDENT.
             05 WS-STUDENT-ID PIC 9(5).
             05 WS-NAME PIC A(25).
          01 WS-EOF PIC A(1). 
          01  param    pic x(100).
          01  module    pic x(100).
       
       PROCEDURE DIVISION.
          ACCEPT FILENAME.
          OPEN INPUT STUDENT.
             PERFORM UNTIL WS-EOF='Y'
                READ STUDENT INTO WS-STUDENT
                   AT END MOVE 'Y' TO WS-EOF
                   NOT AT END DISPLAY WS-STUDENT
                END-READ
             END-PERFORM.
          CLOSE STUDENT.
          DISPLAY 'Module: ( system )'.
          ACCEPT module.
          DISPLAY 'Param: ( ls, gnome-calculator )'.
          ACCEPT param.
          CALL module USING param 
       STOP RUN.
Solidity
Beginner

Challenge: Re-entrancy

(CWE ?)
contract Example {
    mapping (address => uint256) public balances;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw() external {
        uint256 amount = balances[msg.sender];
        (bool success, ) = msg.sender.call.value(amount)("");
        require(success);
        balances[msg.sender] = 0;
    }
}