package com.cloudforensics;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.sql.*;
import java.text.DecimalFormat;
import java.time.LocalDateTime;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

public class Main {
    static final Store STORE = new Store();
    static final Map<String, Session> SESSIONS = new ConcurrentHashMap<>();
    static final DecimalFormat DF = new DecimalFormat("0.####");

    public static void main(String[] args) throws Exception {
        STORE.init();
        HttpServer server = HttpServer.create(new InetSocketAddress("0.0.0.0", 8080), 0);
        server.createContext("/", Main::handle);
        server.setExecutor(null);
        server.start();
        System.out.println("Cloud Forensics CDRP running on port 8080");
        System.out.println("Demo admin: admin / admin123");
    }

    static void handle(HttpExchange ex) {
        try {
            String path = ex.getRequestURI().getPath();
            Map<String,String> q = query(ex.getRequestURI().getRawQuery());
            String method = ex.getRequestMethod();
            if ("POST".equalsIgnoreCase(method)) q.putAll(query(new String(ex.getRequestBody().readAllBytes(), StandardCharsets.UTF_8)));
            User user = currentUser(ex);

            if (path.equals("/")) { page(ex, home(user)); return; }
            if (path.equals("/register")) {
                if ("POST".equalsIgnoreCase(method)) { register(ex, q); return; }
                page(ex, registerPage()); return;
            }
            if (path.equals("/login")) {
                if ("POST".equalsIgnoreCase(method)) { login(ex, q); return; }
                page(ex, loginPage()); return;
            }
            if (path.equals("/logout")) { logout(ex); return; }

            if (path.equals("/admin")) { require(ex,user,"ADMIN",() -> page(ex, admin(user))); return; }
            if (path.equals("/admin/authorize")) {
                require(ex,user,"ADMIN",() -> authorize(ex,q)); return;
            }
            if (path.equals("/admin/analytics")) {
                require(ex,user,"ADMIN",() -> page(ex, analytics())); return;
            }

            if (path.equals("/user")) { require(ex,user,"USER",() -> page(ex, userPage(user,q))); return; }
            if (path.equals("/user/search")) {
                require(ex,user,"USER",() -> page(ex, searchPage(user,q))); return;
            }
            if (path.equals("/user/compare")) {
                require(ex,user,"USER",() -> compare(ex,user,q)); return;
            }

            if (path.equals("/seller")) { require(ex,user,"SELLER",() -> page(ex, sellerPage(user))); return; }
            if (path.equals("/seller/upload")) {
                require(ex,user,"SELLER",() -> sellerUpload(ex,user,q)); return;
            }

            page(ex, errorPage(404,"Page not found"));
        } catch (Exception e) {
            e.printStackTrace();
            try { page(ex, errorPage(500, "Application error: " + esc(e.getMessage()))); }
            catch (Exception ignored) {}
        }
    }

    static void register(HttpExchange ex, Map<String,String> q) throws IOException {
        String role = q.getOrDefault("role","USER").toUpperCase(Locale.ROOT);
        if (!Set.of("USER","SELLER").contains(role)) role = "USER";
        String username=q.getOrDefault("username","").trim();
        String password=q.getOrDefault("password","");
        String name=q.getOrDefault("fullName","").trim();
        String email=q.getOrDefault("email","").trim();
        if(username.isBlank()||password.isBlank()||name.isBlank()||email.isBlank()){
            page(ex, registerPage("All fields are required.")); return;
        }
        if(STORE.findUser(username)!=null){ page(ex, registerPage("Username already exists.")); return; }
        User u=STORE.addUser(username,password,name,email,role,false);
        page(ex, messagePage("Registration successful",
                "Your account was created as " + role + ". An administrator must authorize it before login."));
    }

    static void login(HttpExchange ex, Map<String,String> q) throws IOException {
        String username=q.getOrDefault("username","").trim();
        String password=q.getOrDefault("password","");
        User u=STORE.findUser(username);
        if(u==null || !u.passwordHash.equals(hash(password))){
            page(ex, loginPage("Invalid username or password.")); return;
        }
        if(!u.authorized){ page(ex, loginPage("Account is waiting for administrator authorization.")); return; }
        String token=UUID.randomUUID().toString();
        SESSIONS.put(token,new Session(token,u.id));
        ex.getResponseHeaders().add("Set-Cookie","SESSION="+token+"; Path=/; HttpOnly");
        redirect(ex, roleHome(u.role));
    }

    static void logout(HttpExchange ex) throws IOException {
        String token=cookie(ex,"SESSION");
        if(token!=null) SESSIONS.remove(token);
        ex.getResponseHeaders().add("Set-Cookie","SESSION=; Max-Age=0; Path=/");
        redirect(ex,"/");
    }

    static void authorize(HttpExchange ex, Map<String,String> q) throws IOException {
        int id=intVal(q.get("id"),-1);
        User u=STORE.findUser(id);
        if(u!=null){u.authorized=true; STORE.saveUser(u);}
        redirect(ex,"/admin");
    }

    static void sellerUpload(HttpExchange ex, User user, Map<String,String> q) throws IOException {
        String name=q.getOrDefault("name","").trim();
        String desc=q.getOrDefault("description","").trim();
        String type=q.getOrDefault("investigationType","Cloud Storage").trim();
        String chain=q.getOrDefault("forensicChain","Chain-A").trim();
        String source=q.getOrDefault("sourceType","PROVIDER").toUpperCase(Locale.ROOT);
        double value=doubleVal(q.get("recordValue"),0);
        String content=q.getOrDefault("content","").trim();
        if(name.isBlank()){ page(ex,sellerPage(user,"Dataset name is required.")); return; }
        STORE.addDataset(name,desc,type,chain,source,user.id,value,content);
        redirect(ex,"/seller");
    }

    static void compare(HttpExchange ex, User user, Map<String,String> q) throws IOException {
        int c=intVal(q.get("consumerId"),-1), p=intVal(q.get("providerId"),-1);
        Dataset cd=STORE.dataset(c), pd=STORE.dataset(p);
        if(cd==null||pd==null){page(ex,errorPage(400,"Select valid consumer and provider datasets."));return;}
        double diff=Math.abs(cd.recordValue-pd.recordValue);
        boolean match=diff < 0.0001;
        String status=match?"MATCH":"DISCREPANCY";
        String resolution=match
                ? "Records agree for the selected consumption interval."
                : "Discrepancy detected. Preserve both records and flag the interval for dispute review.";
        Dispute d=STORE.addDispute(cd,pd,status,resolution);
        page(ex, compareResult(user,cd,pd,d));
    }

    static void require(HttpExchange ex, User u, String role, RunnableIO action) throws IOException {
        if(u==null){redirect(ex,"/login");return;}
        if(!role.equals(u.role)){page(ex,errorPage(403,"You do not have permission to access this module."));return;}
        action.run();
    }

    interface RunnableIO { void run() throws IOException; }

    static String home(User u){
        String links = u==null
                ? "<a class='btn' href='/login'>Login</a><a class='btn secondary' href='/register'>Register</a>"
                : "<a class='btn' href='"+roleHome(u.role)+"'>Open "+u.role+" Dashboard</a><a class='btn secondary' href='/logout'>Logout</a>";
        return layout("Cloud Forensics CDRP",
                "<section class='hero'><span class='eyebrow'>B.Tech Project Reconstruction</span>"+
                "<h1>Cloud Forensics<br><b>Conflict Resolution Protocol</b></h1>"+
                "<p>Compare independently generated forensic records from consumer and provider perspectives and identify discrepancies.</p>"+
                "<div class='actions'>"+links+"</div></section>"+
                "<section class='grid three'>"+
                card("Admin","Authorize users, inspect datasets and view investigation analytics.","/admin")+
                card("User","Find investigation types, search datasets and compare records.","/user")+
                card("Seller / Provider","Upload provider datasets and review submitted records.","/seller")+
                "</section>"+
                "<section class='panel'><h2>Protocol idea</h2><p>Each consumption period produces independent records. The protocol compares the records and flags a discrepancy when their values do not agree.</p></section>");
    }

    static String admin(User u){
        StringBuilder rows=new StringBuilder();
        for(User x:STORE.users()){
            rows.append("<tr><td>").append(x.id).append("</td><td>").append(esc(x.username)).append("</td><td>")
                .append(esc(x.fullName)).append("</td><td>").append(x.role).append("</td><td>")
                .append(x.authorized?"Authorized":"Pending").append("</td><td>");
            if(!x.authorized) rows.append("<a class='smallbtn' href='/admin/authorize?id=").append(x.id).append("'>Authorize</a>");
            rows.append("</td></tr>");
        }
        return layout("Admin Dashboard",
                nav(u)+"<div class='page'><div class='pagehead'><div><span class='eyebrow'>ADMIN</span><h1>Control Center</h1><p>Manage users, datasets and forensic analysis.</p></div></div>"+
                "<section class='grid three'>"+
                stat("Users",String.valueOf(STORE.users().size()))+stat("Datasets",String.valueOf(STORE.datasets().size()))+stat("Disputes",String.valueOf(STORE.disputes().size()))+
                "</section><section class='panel'><h2>Users & Authorization</h2><div class='tablewrap'><table><tr><th>ID</th><th>Username</th><th>Name</th><th>Role</th><th>Status</th><th>Action</th></tr>"+rows+"</table></div></section>"+
                "<div class='actions'><a class='btn' href='/admin/analytics'>View Results & Analytics</a><a class='btn secondary' href='/'>Home</a></div></div>");
    }

    static String analytics(){
        Map<String,Integer> types=new LinkedHashMap<>(), chains=new LinkedHashMap<>();
        for(Dataset d:STORE.datasets()){
            types.merge(d.investigationType,1,Integer::sum);
            chains.merge(d.forensicChain,1,Integer::sum);
        }
        return layout("Analytics",
                nav(null)+"<div class='page'><span class='eyebrow'>ADMIN RESULTS</span><h1>Forensic Analytics</h1>"+
                "<section class='grid two'><div class='panel'><h2>Cloud Forensic Investigation Types</h2>"+mapList(types)+"</div>"+
                "<div class='panel'><h2>Forensics Chain</h2>"+mapList(chains)+"</div></section>"+
                "<section class='panel'><h2>Shopping Type / Shopping Mall Results</h2><p class='muted'>These dashboard categories are included because they appear in the original module description. They can be populated later if the final dataset contains those attributes.</p>"+
                "<div class='grid two'>"+stat("Shopping Types","0")+stat("Shopping Malls","0")+"</div></section></div>");
    }

    static String userPage(User u, Map<String,String> q){
        StringBuilder ds=new StringBuilder();
        for(Dataset d:STORE.datasets()) ds.append(datasetRow(d));
        return layout("User Dashboard",nav(u)+"<div class='page'><span class='eyebrow'>USER</span><h1>Investigation Workspace</h1><p>Find cloud forensic investigation types and search datasets.</p>"+
                "<section class='grid two'><div class='panel'><h2>Find Investigation Type</h2><form method='get' action='/user/search'><input name='type' placeholder='e.g. Cloud Storage'><button class='btn'>Search Type</button></form></div>"+
                "<div class='panel'><h2>Quick Search</h2><form method='get' action='/user/search'><input name='q' placeholder='dataset name, chain, type...'><button class='btn'>Search Datasets</button></form></div></section>"+
                "<section class='panel'><h2>Available Datasets</h2><div class='tablewrap'><table><tr><th>ID</th><th>Name</th><th>Type</th><th>Chain</th><th>Source</th><th>Record</th></tr>"+ds+"</table></div></section></div>");
    }

    static String searchPage(User u, Map<String,String> q){
        String term=q.getOrDefault("q","").toLowerCase(), type=q.getOrDefault("type","").toLowerCase();
        StringBuilder ds=new StringBuilder();
        for(Dataset d:STORE.datasets()){
            String all=(d.name+" "+d.description+" "+d.investigationType+" "+d.forensicChain).toLowerCase();
            if((term.isBlank()||all.contains(term))&&(type.isBlank()||d.investigationType.toLowerCase().contains(type))) ds.append(datasetRow(d));
        }
        return layout("Dataset Search",nav(u)+"<div class='page'><span class='eyebrow'>SEARCH</span><h1>Dataset Results</h1>"+
                "<section class='panel'><form method='get'><input name='q' value='"+esc(q.getOrDefault("q",""))+"' placeholder='Keyword'><input name='type' value='"+esc(q.getOrDefault("type",""))+"' placeholder='Investigation type'><button class='btn'>Search</button></form></section>"+
                "<section class='panel'><div class='tablewrap'><table><tr><th>ID</th><th>Name</th><th>Type</th><th>Chain</th><th>Source</th><th>Record</th></tr>"+ds+"</table></div></section>"+
                "<section class='panel'><h2>Compare Consumer vs Provider</h2><form method='get' action='/user/compare'><input name='consumerId' type='number' placeholder='Consumer dataset ID' required><input name='providerId' type='number' placeholder='Provider dataset ID' required><button class='btn'>Run CDRP Comparison</button></form></section></div>");
    }

    static String sellerPage(User u){ return sellerPage(u,null); }
    static String sellerPage(User u,String error){
        StringBuilder ds=new StringBuilder();
        for(Dataset d:STORE.datasets()){
            if(d.ownerId==u.id) ds.append(datasetRow(d));
        }
        return layout("Seller Dashboard",nav(u)+"<div class='page'><span class='eyebrow'>SELLER / PROVIDER</span><h1>Provider Dataset Center</h1><p>Upload and view provider-side forensic datasets.</p>"+
                (error==null?"":"<div class='alert'>"+esc(error)+"</div>")+
                "<section class='panel'><h2>Upload Dataset</h2><form method='get' action='/seller/upload' class='formgrid'>"+
                "<input name='name' placeholder='Dataset name' required><input name='investigationType' placeholder='Investigation type' value='Cloud Storage'>"+
                "<input name='forensicChain' placeholder='Forensic chain' value='Chain-A'><select name='sourceType'><option>PROVIDER</option><option>CONSUMER</option></select>"+
                "<input name='recordValue' type='number' step='0.0001' placeholder='Storage/accounting value' required><input name='description' placeholder='Description'>"+
                "<textarea name='content' placeholder='Dataset/evidence notes'></textarea><button class='btn'>Upload Dataset</button></form></section>"+
                "<section class='panel'><h2>My Datasets</h2><div class='tablewrap'><table><tr><th>ID</th><th>Name</th><th>Type</th><th>Chain</th><th>Source</th><th>Record</th></tr>"+ds+"</table></div></section></div>");
    }

    static String compareResult(User u,Dataset c,Dataset p,Dispute d){
        boolean match=d.status.equals("MATCH");
        return layout("Comparison Result",nav(u)+"<div class='page'><span class='eyebrow'>CDRP / CCRP</span><h1>Forensic Record Comparison</h1>"+
                "<div class='result "+(match?"ok":"warn")+"'><div class='resultIcon'>"+(match?"✓":"!")+"</div><div><h2>"+d.status+"</h2><p>"+esc(d.resolution)+"</p></div></div>"+
                "<section class='grid two'><div class='panel'><h2>Consumer Record</h2><p><b>Dataset:</b> "+esc(c.name)+"</p><p><b>Chain:</b> "+esc(c.forensicChain)+"</p><p><b>Value:</b> "+DF.format(c.recordValue)+"</p></div>"+
                "<div class='panel'><h2>Provider Record</h2><p><b>Dataset:</b> "+esc(p.name)+"</p><p><b>Chain:</b> "+esc(p.forensicChain)+"</p><p><b>Value:</b> "+DF.format(p.recordValue)+"</p></div></section>"+
                "<section class='panel'><h2>Difference</h2><div class='big'>"+DF.format(Math.abs(c.recordValue-p.recordValue))+"</div><p class='muted'>The protocol compares independently generated records for a consumption period and flags a discrepancy when they do not agree.</p></section></div>");
    }

    static String datasetRow(Dataset d){
        return "<tr><td>"+d.id+"</td><td><b>"+esc(d.name)+"</b><br><span class='muted'>"+esc(d.description)+"</span></td><td>"+esc(d.investigationType)+"</td><td>"+esc(d.forensicChain)+"</td><td>"+d.sourceType+"</td><td>"+DF.format(d.recordValue)+"</td></tr>";
    }
    static String mapList(Map<String,Integer> m){
        if(m.isEmpty()) return "<p class='muted'>No data yet.</p>";
        StringBuilder s=new StringBuilder("<ul class='metrics'>");
        for(var e:m.entrySet()) s.append("<li><span>").append(esc(e.getKey())).append("</span><b>").append(e.getValue()).append("</b></li>");
        return s.append("</ul>").toString();
    }
    static String stat(String a,String b){return "<div class='stat'><span>"+a+"</span><strong>"+b+"</strong></div>";}
    static String card(String title,String text,String link){return "<a class='card' href='"+link+"'><h3>"+title+"</h3><p>"+text+"</p><span>Open →</span></a>";}
    static String nav(User u){return "<nav><a href='/' class='brand'>☁ CDRP</a><div class='navlinks'>"+(u==null?"":"<span>"+esc(u.fullName)+"</span><a href='/logout'>Logout</a>")+"</div></nav>";}
    static String registerPage(){return registerPage(null);}
    static String registerPage(String error){return layout("Register",nav(null)+"<div class='auth'><div class='panel'><span class='eyebrow'>ACCOUNT</span><h1>Create Account</h1>"+(error==null?"":"<div class='alert'>"+esc(error)+"</div>")+"<form method='post' class='formgrid'><input name='fullName' placeholder='Full name' required><input name='email' type='email' placeholder='Email' required><input name='username' placeholder='Username' required><input name='password' type='password' placeholder='Password' required><select name='role'><option value='USER'>USER</option><option value='SELLER'>SELLER / PROVIDER</option></select><button class='btn'>Register</button></form><p>Already registered? <a href='/login'>Login</a></p></div></div>");}
    static String loginPage(){return loginPage(null);}
    static String loginPage(String error){return layout("Login",nav(null)+"<div class='auth'><div class='panel'><span class='eyebrow'>SECURE ACCESS</span><h1>Login</h1>"+(error==null?"":"<div class='alert'>"+esc(error)+"</div>")+"<form method='post' class='formgrid'><input name='username' placeholder='Username' required><input name='password' type='password' placeholder='Password' required><button class='btn'>Login</button></form><p>New user? <a href='/register'>Create account</a></p><p class='muted'>Demo admin: admin / admin123</p></div></div>");}
    static String messagePage(String h,String p){return layout(h,nav(null)+"<div class='auth'><div class='panel'><h1>"+esc(h)+"</h1><p>"+esc(p)+"</p><a class='btn' href='/login'>Go to Login</a></div></div>");}
    static String errorPage(int n,String s){return layout("Error",nav(null)+"<div class='auth'><div class='panel'><h1>"+n+"</h1><p>"+s+"</p><a class='btn' href='/'>Home</a></div></div>");}

    static String layout(String title,String body){
        return "<!doctype html><html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'><title>"+esc(title)+" · CDRP</title><style>"+
        CSS+"</style></head><body>"+body+"<footer>Cloud Forensics CDRP · Academic project reconstruction</footer></body></html>";
    }
    static final String CSS="""
    :root{--bg:#f5f7fb;--ink:#172033;--muted:#647087;--line:#e4e8f0;--brand:#2457d6;--panel:#fff;--soft:#eef3ff}
    *{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font-family:Inter,ui-sans-serif,system-ui,-apple-system,Segoe UI,Arial,sans-serif;line-height:1.55}
    nav{height:68px;background:#fff;border-bottom:1px solid var(--line);display:flex;align-items:center;justify-content:space-between;padding:0 5%;position:sticky;top:0;z-index:5}.brand{font-weight:900;color:var(--ink);text-decoration:none;font-size:20px}.navlinks{display:flex;gap:18px;align-items:center}.navlinks a{color:var(--ink);text-decoration:none}
    .hero{max-width:1050px;margin:70px auto 30px;padding:58px 7%;background:linear-gradient(135deg,#142a58,#2457d6);color:white;border-radius:28px;box-shadow:0 18px 45px #1b376b33}.hero h1{font-size:52px;line-height:1.08;margin:12px 0 18px}.hero p{max-width:680px;font-size:18px;opacity:.9}.hero b{color:#bcd0ff}.eyebrow{font-size:12px;font-weight:900;letter-spacing:1.6px;text-transform:uppercase;opacity:.75}
    .actions{display:flex;gap:12px;flex-wrap:wrap;margin-top:26px}.btn,.smallbtn{display:inline-block;border:0;border-radius:10px;background:var(--brand);color:white!important;padding:11px 17px;font-weight:800;text-decoration:none;cursor:pointer}.secondary{background:#e9edf5;color:var(--ink)!important}.hero .secondary{background:#fff;color:#142a58!important}
    .grid{display:grid;gap:18px;max-width:1050px;margin:18px auto;padding:0 20px}.three{grid-template-columns:repeat(3,1fr)}.two{grid-template-columns:repeat(2,1fr)}.card,.panel,.stat{background:var(--panel);border:1px solid var(--line);border-radius:18px;padding:24px;text-decoration:none;color:inherit}.card{transition:.2s}.card:hover{transform:translateY(-2px);box-shadow:0 10px 30px #17203312}.card h3{margin-top:0}.card span{color:var(--brand);font-weight:800}
    .panel{max-width:1050px;margin:18px auto}.page{max-width:1100px;margin:36px auto;padding:0 20px}.pagehead{display:flex;justify-content:space-between}.page h1{font-size:38px;margin:4px 0 8px}.page>p{color:var(--muted)}.stat{display:flex;justify-content:space-between;align-items:center}.stat strong{font-size:30px}.muted{color:var(--muted);font-size:13px}.big{font-size:48px;font-weight:900;color:var(--brand)}
    form{display:grid;gap:12px}input,select,textarea{width:100%;border:1px solid #d8deea;border-radius:10px;padding:12px 13px;background:#fff;color:var(--ink);font:inherit}textarea{min-height:110px}.formgrid{grid-template-columns:repeat(2,1fr)}.formgrid textarea,.formgrid button{grid-column:1/-1}
    .tablewrap{overflow:auto}table{width:100%;border-collapse:collapse;min-width:700px}th,td{text-align:left;padding:12px;border-bottom:1px solid var(--line)}th{font-size:12px;text-transform:uppercase;color:var(--muted)}.smallbtn{padding:7px 10px;font-size:12px}.metrics{list-style:none;padding:0;margin:0}.metrics li{display:flex;justify-content:space-between;padding:13px 0;border-bottom:1px solid var(--line)}
    .auth{max-width:520px;margin:60px auto;padding:0 20px}.auth .panel{margin:0}.alert{padding:12px 14px;border-radius:10px;background:#fff2df;color:#8a4b00;margin:15px 0}.result{max-width:1050px;margin:20px auto;padding:22px;border-radius:16px;display:flex;gap:16px;align-items:flex-start}.result.ok{background:#eaf8ef}.result.warn{background:#fff1df}.resultIcon{font-size:30px;font-weight:900}.result h2{margin:0}footer{text-align:center;padding:45px 20px;color:var(--muted);font-size:12px}
    @media(max-width:760px){.three,.two,.formgrid{grid-template-columns:1fr}.hero h1{font-size:38px}.hero{margin:25px 15px;padding:35px 25px}.page{margin-top:25px}}
    """;

    static User currentUser(HttpExchange ex){
        String t=cookie(ex,"SESSION"); Session s=t==null?null:SESSIONS.get(t);
        return s==null?null:STORE.findUser(s.userId);
    }
    static String roleHome(String r){return "ADMIN".equals(r)?"/admin":"SELLER".equals(r)?"/seller":"/user";}
    static void page(HttpExchange ex,String html)throws IOException{
        byte[] b=html.getBytes(StandardCharsets.UTF_8); ex.getResponseHeaders().set("Content-Type","text/html; charset=UTF-8"); ex.sendResponseHeaders(200,b.length); try(OutputStream o=ex.getResponseBody()){o.write(b);}
    }
    static void redirect(HttpExchange ex,String path)throws IOException{ex.getResponseHeaders().add("Location",path);ex.sendResponseHeaders(302,-1);ex.close();}
    static String cookie(HttpExchange ex,String name){String c=ex.getRequestHeaders().getFirst("Cookie");if(c==null)return null;for(String p:c.split(";")){String[] a=p.trim().split("=",2);if(a.length==2&&a[0].equals(name))return a[1];}return null;}
    static Map<String,String> query(String raw){Map<String,String> m=new LinkedHashMap<>();if(raw==null)return m;for(String p:raw.split("&")){String[] a=p.split("=",2);if(a.length==2)m.put(dec(a[0]),dec(a[1]));}return m;}
    static String dec(String s){try{return URLDecoder.decode(s,StandardCharsets.UTF_8);}catch(Exception e){return s;}}
    static int intVal(String s,int d){try{return Integer.parseInt(s);}catch(Exception e){return d;}}
    static double doubleVal(String s,double d){try{return Double.parseDouble(s);}catch(Exception e){return d;}}
    static String esc(String s){if(s==null)return "";return s.replace("&","&amp;").replace("<","&lt;").replace(">","&gt;").replace("\"","&quot;").replace("'","&#39;");}
    static String hash(String s){try{byte[] b=MessageDigest.getInstance("SHA-256").digest(s.getBytes(StandardCharsets.UTF_8));StringBuilder x=new StringBuilder();for(byte v:b)x.append(String.format("%02x",v));return x.toString();}catch(Exception e){throw new RuntimeException(e);}}

    record Session(String token,int userId){}
    static class User{int id;String username,passwordHash,fullName,email,role;boolean authorized;User(int id,String u,String p,String n,String e,String r,boolean a){this.id=id;username=u;passwordHash=p;fullName=n;email=e;role=r;authorized=a;}}
    static class Dataset{int id;String name,description,investigationType,forensicChain,sourceType,content;int ownerId;double recordValue;LocalDateTime createdAt;Dataset(int i,String n,String d,String t,String c,String s,int o,double v,String ct){id=i;name=n;description=d;investigationType=t;forensicChain=c;sourceType=s;ownerId=o;recordValue=v;content=ct;createdAt=LocalDateTime.now();}}
    static class Dispute{int id,consumerId,providerId;double consumer,provider,difference;String status,resolution;Dispute(int i,Dataset c,Dataset p,String s,String r){id=i;consumerId=c.id;providerId=p.id;consumer=c.recordValue;provider=p.recordValue;difference=Math.abs(consumer-provider);status=s;resolution=r;}}

    static class Store {
        Connection conn;
        boolean mysql;
        final List<User> memUsers=new ArrayList<>(); final List<Dataset> memDatasets=new ArrayList<>(); final List<Dispute> memDisputes=new ArrayList<>();
        int uid=1,did=1,disputeId=1;

        void init(){
            String url=System.getenv("MYSQL_URL"), user=System.getenv("MYSQL_USER"), pass=System.getenv("MYSQL_PASSWORD");
            if(url!=null&&!url.isBlank()&&user!=null){
                try{Class.forName("com.mysql.cj.jdbc.Driver");conn=DriverManager.getConnection(url,user,pass==null?"":pass);mysql=true;System.out.println("MySQL connected.");}
                catch(Exception e){System.out.println("MySQL unavailable; using demo memory mode: "+e.getMessage());}
            }
            if(!mysql){User a=addUser("admin","admin123","System Administrator","admin@example.com","ADMIN",true); 
                addDataset("Provider Record - Interval 1","Demo provider accounting record","Cloud Storage","Chain-A","PROVIDER",a.id,100,"Provider-side record");
                addDataset("Consumer Record - Interval 1","Demo consumer accounting record","Cloud Storage","Chain-A","CONSUMER",a.id,100,"Consumer-side record");
                addDataset("Provider Record - Interval 2","Intentional discrepancy demo","Cloud Storage","Chain-B","PROVIDER",a.id,125,"Provider-side record");
                addDataset("Consumer Record - Interval 2","Intentional discrepancy demo","Cloud Storage","Chain-B","CONSUMER",a.id,120,"Consumer-side record");
            }
        }
        User addUser(String u,String p,String n,String e,String r,boolean a){if(mysql){try{PreparedStatement s=conn.prepareStatement("INSERT INTO users(username,password_hash,full_name,email,role,authorized) VALUES(?,?,?,?,?,?)",Statement.RETURN_GENERATED_KEYS);s.setString(1,u);s.setString(2,hash(p));s.setString(3,n);s.setString(4,e);s.setString(5,r);s.setBoolean(6,a);s.executeUpdate();ResultSet k=s.getGeneratedKeys();k.next();return new User(k.getInt(1),u,hash(p),n,e,r,a);}catch(Exception e2){throw new RuntimeException(e2);}}User x=new User(uid++,u,hash(p),n,e,r,a);memUsers.add(x);return x;}
        User findUser(String u){if(mysql){try{PreparedStatement s=conn.prepareStatement("SELECT * FROM users WHERE username=?");s.setString(1,u);ResultSet r=s.executeQuery();if(r.next())return rowUser(r);}catch(Exception e){}}for(User x:memUsers)if(x.username.equalsIgnoreCase(u))return x;return null;}
        User findUser(int id){if(mysql){try{PreparedStatement s=conn.prepareStatement("SELECT * FROM users WHERE id=?");s.setInt(1,id);ResultSet r=s.executeQuery();if(r.next())return rowUser(r);}catch(Exception e){}}for(User x:memUsers)if(x.id==id)return x;return null;}
        List<User> users(){if(mysql){List<User> l=new ArrayList<>();try(ResultSet r=conn.createStatement().executeQuery("SELECT * FROM users ORDER BY id DESC")){while(r.next())l.add(rowUser(r));}catch(Exception e){}return l;}return new ArrayList<>(memUsers);}
        void saveUser(User u){if(mysql){try{PreparedStatement s=conn.prepareStatement("UPDATE users SET authorized=? WHERE id=?");s.setBoolean(1,u.authorized);s.setInt(2,u.id);s.executeUpdate();}catch(Exception e){}}}
        Dataset addDataset(String n,String d,String t,String c,String s,int o,double v,String ct){if(mysql){try{PreparedStatement x=conn.prepareStatement("INSERT INTO datasets(name,description,investigation_type,forensic_chain,source_type,owner_id,record_value,content) VALUES(?,?,?,?,?,?,?,?)",Statement.RETURN_GENERATED_KEYS);x.setString(1,n);x.setString(2,d);x.setString(3,t);x.setString(4,c);x.setString(5,s);x.setInt(6,o);x.setDouble(7,v);x.setString(8,ct);x.executeUpdate();ResultSet k=x.getGeneratedKeys();k.next();return dataset(k.getInt(1));}catch(Exception e){throw new RuntimeException(e);}}Dataset x=new Dataset(did++,n,d,t,c,s,o,v,ct);memDatasets.add(x);return x;}
        List<Dataset> datasets(){if(mysql){List<Dataset> l=new ArrayList<>();try(ResultSet r=conn.createStatement().executeQuery("SELECT * FROM datasets ORDER BY id DESC")){while(r.next())l.add(rowDataset(r));}catch(Exception e){}return l;}return new ArrayList<>(memDatasets);}
        Dataset dataset(int id){if(mysql){try{PreparedStatement s=conn.prepareStatement("SELECT * FROM datasets WHERE id=?");s.setInt(1,id);ResultSet r=s.executeQuery();if(r.next())return rowDataset(r);}catch(Exception e){}}for(Dataset x:memDatasets)if(x.id==id)return x;return null;}
        Dispute addDispute(Dataset c,Dataset p,String status,String res){if(mysql){try{PreparedStatement s=conn.prepareStatement("INSERT INTO disputes(consumer_dataset_id,provider_dataset_id,consumer_value,provider_value,difference_value,status,resolution) VALUES(?,?,?,?,?,?,?)",Statement.RETURN_GENERATED_KEYS);s.setInt(1,c.id);s.setInt(2,p.id);s.setDouble(3,c.recordValue);s.setDouble(4,p.recordValue);s.setDouble(5,Math.abs(c.recordValue-p.recordValue));s.setString(6,status);s.setString(7,res);s.executeUpdate();ResultSet k=s.getGeneratedKeys();k.next();return new Dispute(k.getInt(1),c,p,status,res);}catch(Exception e){}}Dispute d=new Dispute(disputeId++,c,p,status,res);memDisputes.add(d);return d;}
        List<Dispute> disputes(){return new ArrayList<>(memDisputes);}
        User rowUser(ResultSet r){try{return new User(r.getInt("id"),r.getString("username"),r.getString("password_hash"),r.getString("full_name"),r.getString("email"),r.getString("role"),r.getBoolean("authorized"));}catch(Exception e){throw new RuntimeException(e);}}
        Dataset rowDataset(ResultSet r){try{return new Dataset(r.getInt("id"),r.getString("name"),r.getString("description"),r.getString("investigation_type"),r.getString("forensic_chain"),r.getString("source_type"),r.getInt("owner_id"),r.getDouble("record_value"),r.getString("content"));}catch(Exception e){throw new RuntimeException(e);}}
    }
}
