// Traffic V2 production-payload signer: ORIGINAL Keychain items ONLY.
// Source-only; no signer enrollment, key export, root install or publication.
import Foundation
import CryptoKit
import Security
import Darwin

func hold(_ why: String) -> Never {
    fputs("TRAFFIC_V2_NATIVE_SIGN_HOLD_\(why)\n", stderr)
    exit(2)
}
func digest(_ data: Data) -> String {
    SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
}
struct Identity {
    let service: String
    let account: String
    let pemSHA: String
}
let roles: [String: Identity] = [
    "owner": Identity(service:"aoe2war.traffic-v2.owner-ed25519.v1",
                      account:"Emaren-github-15059910",
                      pemSHA:"1cdbfb2a532cd6fd1aea1f82f0b5fdc9865133a080d21ecda1837ffd91b91469"),
    "upstream": Identity(service:"aoe2war.traffic-v2.upstream-ed25519.v1",
                         account:"Emaren-github-15059910-upstream",
                         pemSHA:"28065defa7c9c48ebde916f19a90a82409274f8ce62d8aea94a5cb39b8b743de"),
    "classifier": Identity(service:"aoe2war.traffic-v2.classifier-ed25519.v1",
                           account:"Emaren-github-15059910-classifier",
                           pemSHA:"f445fc5a38b34ae11965fd0db1d28636bb86417ba9d6a63d1ae94886c805316b")
]
let frozenHistoricalSHA = "84150e4921197efd925fa2d9abccee37154d45a68b6f72e25df57dfc4e2d07b4"
let dayFields=Set(["schema","project_slug","day","historical_release_sha256",
 "source_epoch_sha256","host_rules_sha256","page_state_sha256",
 "source_snapshot_rowid","forward_prefix_rowid","source_rows",
 "source_page_chain_sha256","missing_insertion_receipts","invalid_insertion_clocks",
 "upstream_log_closed_through_utc","writer_receipts_closed_through_utc",
 "global_ip_model_sha256","canonical_sessions_sha256","cross_midnight_carry_sha256",
 "late_arrival_stability_sha256","total","potential","confirmed"])
let v3DayFields=dayFields.subtracting(["global_ip_model_sha256","canonical_sessions_sha256",
                                      "cross_midnight_carry_sha256"]).union([
 "daily_model_sha256","observation_sha256","carry_sha256","classifier_dependencies_sha256",
 "normalized_input_sha256","source_evidence_sha256"])
let delegationFields=Set(["schema","delegation_id","project","approved_by",
 "issued_at_utc","expires_at_utc","earliest_utc_day","latest_utc_day",
 "max_completed_day_age_days","max_days_per_run","source_commit_sha",
 "source_database_dev","source_database_ino","ingest_service_loaded_sha256",
 "traffic_api_source_sha256","website_gap_renderer_sha256","upstream_key_sha256",
 "classifier_key_sha256","historical_release_sha256","gap_aware_api_and_chart",
 "no_historical_corrections"])
let stateFields=Set(["schema","delegation_sha256","delegation_id","status",
                     "revision","effective_at_utc"])
func validHex(_ value: Any?, length: Int = 64) -> Bool {
    guard let x = value as? String, x.count == length else {return false}
    return x.utf8.allSatisfy {($0 >= 48 && $0 <= 57) || ($0 >= 97 && $0 <= 102)}
}
func dateUTC(_ text: String) -> Date? {
    let formatter=ISO8601DateFormatter()
    if let time=formatter.date(from:text) { return time }
    formatter.formatOptions=[.withInternetDateTime,.withFractionalSeconds]
    return formatter.date(from:text)
}
func check(_ obj:[String:Any], _ role:String, _ kind:String) {
    var fields:Set<String>
    var schema:String
    switch kind {
    case "day":
        guard role=="upstream" || role=="classifier" else { hold("ROLE_KIND_DENIED") }
        let v3 = obj["schema"] as? String == "traffic.public-audience.v3.dual-witness-day.v1"
        fields=v3 ? v3DayFields : dayFields
        schema=v3 ? "traffic.public-audience.v3.dual-witness-day.v1" : "traffic.public-audience.v2.dual-witness-day.v1"
        guard obj["project_slug"] as? String=="aoe2hdbets",
          obj["historical_release_sha256"] as? String==frozenHistoricalSHA,
          (["source_epoch_sha256","host_rules_sha256","page_state_sha256",
           "source_page_chain_sha256","late_arrival_stability_sha256"] +
           (v3 ? ["daily_model_sha256","observation_sha256","carry_sha256",
                  "classifier_dependencies_sha256","normalized_input_sha256","source_evidence_sha256"] :
                 ["global_ip_model_sha256","canonical_sessions_sha256","cross_midnight_carry_sha256"]))
                 .allSatisfy({validHex(obj[$0])}),
          let day=obj["day"] as? String,day.count==10,
          day >= (v3 ? "2026-11-23" : "2026-10-20"),day<String(ISO8601DateFormatter().string(from:Date()).prefix(10)),
          let t=obj["total"] as? Int,let p=obj["potential"] as? Int,
          let c=obj["confirmed"] as? Int,t>0,t>=p,p>=c,c>=0,
          obj["missing_insertion_receipts"] as? Int==0,
          obj["invalid_insertion_clocks"] as? Int==0,
          let rows=obj["source_rows"] as? Int,rows>0,
          let snap=obj["source_snapshot_rowid"] as? Int,snap>0,
          obj["forward_prefix_rowid"] as? Int==snap
        else {hold("DAY_EVIDENCE_SHAPE_OR_PREFIX")}
        guard let remote=obj["upstream_log_closed_through_utc"] as? String,
          let writer=obj["writer_receipts_closed_through_utc"] as? String,
          let start=dateUTC(day+"T00:00:00Z"),
          let end=Calendar(identifier:.gregorian).date(byAdding:.day,value:1,to:start),
          let closure=dateUTC(remote),let written=dateUTC(writer),
          closure>=end.addingTimeInterval(1860),written>=end.addingTimeInterval(1860)
        else {hold("DAY_FINALITY_CLOCK")}
    case "delegation":
        guard role=="owner" else {hold("ROLE_KIND_DENIED")}
        fields=delegationFields;schema="traffic.public-audience.v2.daily-delegation.v1"
        guard obj["project"] as? String=="aoe2hdbets",
          obj["historical_release_sha256"] as? String==frozenHistoricalSHA,
          ["delegation_id","ingest_service_loaded_sha256","traffic_api_source_sha256",
           "website_gap_renderer_sha256","upstream_key_sha256","classifier_key_sha256"]
           .allSatisfy({validHex(obj[$0])}),
          obj["approved_by"] as? String=="Emaren",
          obj["gap_aware_api_and_chart"] as? Bool==true,
          obj["no_historical_corrections"] as? Bool==true,
          let maximum=obj["max_days_per_run"] as? Int,(1...7).contains(maximum),
          let age=obj["max_completed_day_age_days"] as? Int,(1...3).contains(age),
          let source=obj["source_commit_sha"] as? String,validHex(source,length:40),
          obj["upstream_key_sha256"] as? String==roles["upstream"]?.pemSHA,
          obj["classifier_key_sha256"] as? String==roles["classifier"]?.pemSHA,
          let issued=obj["issued_at_utc"] as? String,
          let expires=obj["expires_at_utc"] as? String,
          let issuedAt=dateUTC(issued),let expiresAt=dateUTC(expires),
          issuedAt<=Date(),Date()<expiresAt,
          expiresAt<=issuedAt.addingTimeInterval(35*86400)
        else {hold("DELEGATION_BOUNDARY")}
    case "state":
        guard role=="owner" else {hold("ROLE_KIND_DENIED")}
        fields=stateFields;schema="traffic.public-audience.v2.delegation-revocation-state.v1"
        guard let s=obj["status"] as? String,(s=="ACTIVE" || s=="REVOKED"),
          let rev=obj["revision"] as? Int,rev>0,
          validHex(obj["delegation_id"]),validHex(obj["delegation_sha256"])
        else {hold("REVOCATION_STATE_SCOPE")}
    default:hold("UNRECOGNIZED_KIND")
    }
    guard Set(obj.keys)==fields,obj["schema"] as? String==schema
    else {hold("SCHEMA_FIELDS_DRIFT")}
}
func input(_ path:String,_ role:String,_ kind:String)->(Data,String) {
    guard let data=try? Data(contentsOf:URL(fileURLWithPath:path)),
      data.count>0,data.count<=16384,
      let json=try? JSONSerialization.jsonObject(with:data),
      let obj=json as? [String:Any],
      let encoded=try? JSONSerialization.data(withJSONObject:obj,
          options:[.sortedKeys,.withoutEscapingSlashes]),encoded==data
    else {hold("NONCANONICAL_OR_OVERSIZED_JSON")}
    check(obj,role,kind)
    return (data,digest(data))
}
func protect(_ path:String,_ exists:Bool) {
    guard path.hasPrefix("/") && !path.contains("/../") else {hold("PATH_ESCAPE")}
    let parent=URL(fileURLWithPath:path).deletingLastPathComponent().path
    var folder=stat()
    guard lstat(parent,&folder)==0,(folder.st_mode & S_IFMT)==S_IFDIR,
      folder.st_uid==getuid(),(folder.st_mode & 0o777)==0o700
    else {hold("PARENT_PRIVACY")}
    var file=stat()
    let found=lstat(path,&file)==0
    if exists {
      guard found,(file.st_mode & S_IFMT)==S_IFREG,file.st_nlink==1,
        file.st_uid==getuid(),(file.st_mode & 0o777)==0o600
      else {hold("INPUT_NOT_OWNER_PRIVATE_REGULAR")}
    } else if found {hold("OUTPUT_ALREADY_EXISTS")}
}
func pem(_ publicKey:Data)->Data {
    let prefix=Data([0x30,0x2a,0x30,0x05,0x06,0x03,0x2b,0x65,0x70,0x03,0x21,0x00])
    let b64=(prefix+publicKey).base64EncodedString()
    var lines:[String]=[]
    var i=b64.startIndex
    while i<b64.endIndex {
      let end=b64.index(i,offsetBy:64,limitedBy:b64.endIndex) ?? b64.endIndex
      lines.append(String(b64[i..<end]));i=end
    }
    return Data(("-----BEGIN PUBLIC KEY-----\n" + lines.joined(separator:"\n") +
                 "\n-----END PUBLIC KEY-----\n").utf8)
}
let args=Array(CommandLine.arguments.dropFirst())
let mode=args.first ?? ""
guard (mode=="--validate-fixture" && args.count==7) ||
      (mode=="--sign" && args.count==11),
      args[1]=="--role",args[3]=="--kind",args[5]=="--input",
      roles[args[2]] != nil
else {hold("USAGE_FIXED_ORDER_ROLE_KIND_INPUT_DIGEST")}
let role=args[2],kind=args[4],path=args[6]
if mode=="--sign" {
  guard isatty(STDIN_FILENO)==1,isatty(STDERR_FILENO)==1,
        getenv("SSH_CONNECTION")==nil,getenv("SSH_TTY")==nil,getuid() != 0
  else {hold("PHYSICAL_LOCAL_TERMINAL_REQUIRED")}
  #if arch(x86_64)
  guard role=="upstream" else {hold("INTEL_UPSTREAM_ONLY")}
  #elseif arch(arm64)
  guard role=="owner" || role=="classifier" else {hold("M1_OWNER_CLASSIFIER_ONLY")}
  #else
  hold("MACHINE_ARCH_NOT_ADMITTED")
  #endif
  let dir=NSHomeDirectory()+"/Library/Application Support/AoE2WAR/TrafficV2SigningRequests/"+role+"/"
  guard path.hasPrefix(dir),args[8].hasPrefix(dir),path != args[8]
  else {hold("UNBOUND_SIGNING_REQUEST_PATH")}
  protect(path,true); protect(args[8],false)
}
// Do not inspect arbitrary production input paths or Keychain until the
// physical interactive identity and owner-private request directory pass.
let (payload,payloadSHA)=input(path,role,kind)
if mode=="--validate-fixture" {
    print("TRAFFIC_V2_SCHEMA_ONLY_VALID=true")
    print("PAYLOAD_SHA256=\(payloadSHA)")
    print("PRODUCTION_SIGNATURE_CREATED=false")
    exit(0)
}
guard args[7]=="--signature-output",args[9]=="--approve-sha256",
      args[10]==payloadSHA
else {hold("OPERATOR_EXACT_HASH_APPROVAL_REQUIRED")}
print("REVIEW role=\(role) kind=\(kind) canonical_sha256=\(payloadSHA)")
fputs("Type APPROVE \(String(payloadSHA.prefix(16))) \(role) to sign: ",stderr)
guard readLine()=="APPROVE \(String(payloadSHA.prefix(16))) \(role)"
else {hold("OWNER_DECLINED")}
let id=roles[role]!
let attributes:[String:Any]=[
  kSecClass as String:kSecClassGenericPassword,
  kSecAttrService as String:id.service,
  kSecAttrAccount as String:id.account,
  kSecReturnData as String:true,
  kSecMatchLimit as String:kSecMatchLimitOne
]
var item:CFTypeRef?
guard SecItemCopyMatching(attributes as CFDictionary,&item)==errSecSuccess,
  let raw=item as? Data,raw.count==32,
  let key=try? Curve25519.Signing.PrivateKey(rawRepresentation:raw)
else {hold("ORIGINAL_KEYCHAIN_IDENTITY_UNAVAILABLE")}
guard digest(pem(key.publicKey.rawRepresentation))==id.pemSHA
else {hold("PUBLIC_IDENTITY_PIN_DRIFT")}
guard let sig=try? key.signature(for:payload),sig.count==64,
      key.publicKey.isValidSignature(sig,for:payload)
else {hold("SIGNATURE_SELF_VERIFICATION")}
let detached=sig.base64EncodedString().replacingOccurrences(of:"+",with:"-")
 .replacingOccurrences(of:"/",with:"_").replacingOccurrences(of:"=",with:"")
guard detached.count==86 else {hold("BASE64URL_ENCODING")}
umask(0o077)
let fd=open(args[8],O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW,0o600)
guard fd>=0 else {hold("OUTPUT_CREATE_DENIED")}
let written=detached.withCString{ write(fd,$0,detached.utf8.count) }
let flushed=fsync(fd),closed=close(fd)
guard written==detached.utf8.count,flushed==0,closed==0
else {hold("PARTIAL_OUTPUT_REQUIRES_INSPECTION")}
print("TRAFFIC_V2_PRODUCTION_PAYLOAD_SIGNATURE_CREATED=true")
print("ROLE=\(role) KIND=\(kind) PAYLOAD_SHA256=\(payloadSHA)")
print("DETACHED_SIGNATURE_SHA256=\(digest(sig))")
print("PUBLICATION_OR_ROOT_ADMITTED=false")
