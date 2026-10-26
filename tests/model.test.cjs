const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const model = vm.createContext({});
vm.runInContext(fs.readFileSync('ui0237/State.js','utf8'), model);
function fixture() {
 return {schema_version:'1.0', collected_at:'2026-10-20T00:00:00Z', checks:[{check_id:'security.home.permissions', status:'attention', severity:'medium', summary:'Review home mode', confidence:'high', recommendation:'Review before changing', reversibility:'Undo with receipt', evidence:[{source:'metadata',value:'mode=0702'}],remediation_action_ids:['home.remove_world_write']}]};
}
test('valid structured result', () => assert.equal(model.validate(fixture()).checks.length,1));
test('missing or invalid schema', () => {assert.throws(()=>model.validate(null));assert.throws(()=>model.validate({schema_version:'99'}));});
test('oversized field rejected', () => {const f=fixture();f.checks[0].summary='x'.repeat(2049);assert.throws(()=>model.validate(f));});
test('invalid classifications rejected', () => {const f=fixture();f.checks[0].status='safe';assert.throws(()=>model.validate(f));});
test('duplicate check rejected', () => {const f=fixture();f.checks.push(f.checks[0]);assert.throws(()=>model.validate(f));});
test('oversized list rejected', () => {const f=fixture();f.checks=Array.from({length:513},(_,i)=>({...f.checks[0],check_id:'test.check'+i}));assert.throws(()=>model.validate(f));});
test('hostile content treated as data', () => {const f=fixture();f.checks[0].summary='<img src=x onerror="run()">; sudo reboot';assert.equal(model.validate(f).checks[0].summary,f.checks[0].summary);});
test('filter only affects matching section', () => {assert.equal(model.filtered(fixture().checks,'Performance','',false).length,0);assert.equal(model.filtered(fixture().checks,'Security','home',true).length,1);});
test('severity ordering', () => {const f=fixture();f.checks.push({...f.checks[0],check_id:'system.os',severity:'critical'});assert.equal(model.filtered(f.checks,'Overview','',false)[0].severity,'critical');});
test('unknown action cannot become executable', () => {const f=fixture();f.checks[0].remediation_action_ids=['shell.anything'];assert.equal(model.supportedAction(f.checks[0]),false);});
test('coverage counts separate unknown', () => {const f=fixture();f.checks.push({...f.checks[0],status:'unavailable'});assert.equal(model.counts(f.checks).review,1);assert.equal(model.counts(f.checks).unavailable,1);});
test('evidence as literal string', () => {assert.equal(model.evidence(fixture().checks[0]),'metadata\nmode=0702');});
test('overview surfaces action instead of every normal observation', () => {const f=fixture();f.checks.push({...f.checks[0],check_id:'system.normal',status:'pass'});assert.equal(model.filtered(f.checks,'Overview','',false).length,1);assert.equal(model.filtered(f.checks,'Diagnostics','',false).length,2);});
function softwareFixture() {return {schema:2,observed_at:'2026-10-21T00:00:00Z',fresh:false,limits:[],items:[{name:'php',installed:'8.5.11-1',available:'8.5.12-1',source:'mise',status:'update available',advisories:[]}]};}
test('software versions and update filtering',()=>{const s=model.software(softwareFixture());assert.equal(model.softwareItems(s.items,'php',true).length,1);assert.equal(model.softwareItems(s.items,'node',false).length,0);});
test('software rejects hostile version and unsupported source',()=>{const s=softwareFixture();s.items[0].available='$(curl attacker)';assert.throws(()=>model.software(s));s.items[0].available=null;s.items[0].source='shell';assert.throws(()=>model.software(s));s.items[0].source='pacman';s.items[0].name=123;assert.throws(()=>model.software(s));});
test('advisory notices reject executable links',()=>{const s=softwareFixture();s.items[0].advisories=[{id:'javascript:run()',severity:'critical',issues:[]}];assert.throws(()=>model.software(s));});
test('update controls allow enrolled user managers and exclude core packages and launchers',()=>{
 assert.equal(model.canUpdate({source:'pacman',active:true,available:'2'}),false);
 assert.equal(model.canUpdate({source:'local launcher',active:true,available:'2'}),false);
 assert.equal(model.canUpdate({source:'mise',active:true,available:'2'}),true);
 assert.equal(model.canUpdate({source:'mise',active:false,available:'2'}),false);
 assert.equal(model.canUpdate({source:'uv tool'}),true);
 assert.equal(model.canUpdate({source:'Flatpak user'}),true);
});
test('managed apps omit inactive versions and unverified launchers without losing inventory',()=>{
 const items=[{name:'node',source:'mise',installed:'24',active:true,available:null,advisories:[]},{name:'node',source:'mise',installed:'22',active:false,available:null,advisories:[]},{name:'custom',source:'local launcher',installed:'unknown',available:null,advisories:[]}];
 assert.equal(model.appItems(items,'','Managed').length,1);
 assert.equal(model.appItems(items,'','All versions').length,3);
 assert.equal(model.appItems(items,'','Unverified')[0].name,'custom');
});


function updateFixture() {return {schema:2,operation:'user-application-update',digest:'a'.repeat(64),name:'node',source:'mise',target:'mise:node',installed:'24',available:'24.1',scope:'One global tool',impact:'Save work',recovery:'Verify after restart',command:['/usr/bin/mise','--yes','upgrade','--global','node']};}
test('reviewed update plan requires an enrolled manager and exact target',()=>{
 assert.equal(model.updatePlan(updateFixture()).target,'mise:node');
 for (const change of [{source:'pacman'},{command:['/bin/sh','-c','evil']},{target:'mise:other'},{digest:'bad'}]) assert.throws(()=>model.updatePlan({...updateFixture(),...change}));
});

test('Updates excludes completed apps and retained old versions; Installed retains inventory',()=>{
 const rows=[
 {name:'node',source:'mise',installed:'24.22.0',available:null,active:false,advisories:[]},
 {name:'node',source:'mise',installed:'24.22.1',available:null,active:true,advisories:[]},
 {name:'gh',source:'mise',installed:'2.102.1',available:'2.103.0',active:true,advisories:[]},
 {name:'ruff',source:'uv tool',installed:'1.0',available:null,advisories:[]}];
 assert.deepEqual(model.appItems(rows,'','Updates').map(i=>i.name),['gh']);
 assert.equal(model.appItems(rows,'','Installed').length,3);
 rows[2].installed='2.103.0';rows[2].available=null;
 assert.equal(model.appItems(rows,'','Updates').length,0);
});

test('finding inspection is allowlisted and AI fix request grants no execution',()=>{
 assert.equal(model.inspection('unknown.action'),null);
 assert.equal(model.inspection('network.listeners').command[0],'/usr/bin/ss');
 assert.equal(model.inspection('startup.units.system_failed').command.includes('--failed'),true);
 assert.equal(model.inspection('startup.units.user_failed').command.includes('--user'),true);
 const request=model.fixQuestion({check_id:'network.listeners',summary:'Two network listeners'},{action:'Check intended sharing'});
 assert.match(request,/Check intended sharing/);
 assert.match(request,/how to undo/);
 assert.match(request,/Do not apply changes or assume approval/);
 assert.equal(model.supportedAction({remediation_action_ids:['model.invented.fix']}),false);
});

test('long finding context cannot truncate fix-plan instructions',()=>{
 const request=model.fixQuestion({check_id:'network.listeners',summary:'x'.repeat(2048)},{action:'y'.repeat(600)});
 assert.ok(request.length<=1000);
 assert.match(request,/Do not apply changes or assume approval/);
 assert.match(request,/network.listeners/);
});

test('repair plans reject arbitrary action and command payloads',()=>{
 const plan={schema:1,action_id:'security.enable-aslr',digest:'a'.repeat(64),privileged:true,commands:[['/usr/bin/sysctl','-w','kernel.randomize_va_space=2']],check_id:'security.kernel.aslr',target:'kernel.randomize_va_space',title:'Enable ASLR',impact:'Runtime setting',undo:'Restore prior value',verification:'Read value',implementation:'Fixed command'};
 assert.equal(model.repairPlan(plan).action_id,'security.enable-aslr');
 assert.throws(()=>model.repairPlan({...plan,action_id:'ai.execute'}));
 assert.throws(()=>model.repairPlan({...plan,commands:[['/usr/bin/sh','-c','anything']]}));
 assert.throws(()=>model.repairPlan({...plan,commands:[['/usr/bin/sysctl','-w','different.key=0']]}));
});

test('affected ports show actual observed scope without inventing application ownership',()=>{
 const c={check_id:'network.listeners',evidence:[{source:'ss protocol/port/scope; first 16 only',value:JSON.stringify([{protocol:'udp',port:5353,bind_scope:'wildcard'},{protocol:'tcp',port:8000,bind_scope:'loopback'}])}]};
 assert.match(model.affected(c),/UDP 5353 \(all network interfaces\)/);
 assert.match(model.affected(c),/TCP 8000 \(this machine only\)/);
 c.evidence[0].value='not json';assert.match(model.affected(c),/inspect locally/);
});
test('repair follow-up distinguishes cleared remaining and unknown instead of hiding missing checks',()=>{
 assert.equal(model.followUp([{check_id:'x',status:'pass'}],'x').state,'resolved');
 assert.equal(model.followUp([{check_id:'x',status:'attention'}],'x').state,'remaining');
 for(const checks of [[],[{check_id:'x',status:'unavailable'}],[{check_id:'x',status:'error'}]]) assert.equal(model.followUp(checks,'x').state,'unknown');
});
test('activity validates outcomes and treats recovery instructions as plain data',()=>{
 const row={id:'repair:123',kind:'repair',at:'',title:'Demo',target:'demo.service',detail:'No result',recovery:'$(do-not-execute)',versions:'',check_id:'startup.units.user_failed',outcome:'incomplete'};
 assert.equal(model.activityRows({entries:[row],limits:[]}).entries[0].recovery,row.recovery);
 assert.throws(()=>model.activityRows({entries:[{...row,outcome:'fixed'}],limits:[]}));
 assert.throws(()=>model.activityRows({entries:[{...row,detail:123}],limits:[]}));
});

test('unsupported conditions offer instructions rather than an apply action',()=>{
 assert.equal(model.canReviewRepair({check_id:'security.boot.secure_boot'}),false);
 assert.equal(model.canReviewRepair({check_id:'security.kernel.aslr'}),true);
 assert.equal(model.canReviewRepair({check_id:'network.listeners'}),true);
});

test('protection priorities put exact known-exploited matches first',()=>{
 const items=[{name:'other',advisories:[{id:'GHSA-b',severity:'critical'}]},{name:'urgent',advisories:[{id:'GHSA-a',severity:'unknown',known_exploited:true}]}];
 assert.equal(model.protectionRisks({items})[0].item.name,'urgent');
});
test('protection cannot claim continuous monitoring or zero-day assurance',()=>{
 const data={schema:1,scanner:{installed:false,ready:false,message:'Set up scanner',coverage:'On demand'},last_scan:null,limits:[],continuous_monitoring:false,zero_day_assurance:false};
 assert.equal(model.protectionState(data).scanner.ready,false);
 assert.throws(()=>model.protectionState({...data,zero_day_assurance:true}));
 assert.throws(()=>model.malwareResult({schema:1,outcome:'safe',detections:[]}));
});


test('protection maintenance does not accept malformed health or remote command text',()=>{
 const base={schema:1,scanner:{installed:true,ready:true,message:'Ready',coverage:'Selected files'},last_scan:null,limits:[],continuous_monitoring:false,zero_day_assurance:false};
 const updates={automatic:true,issues:[],engines:[{name:'falco',installed:'0.45.1',latest:'0.45.2',update_available:true}],policy_version:'0.2.18',plugin_update:'Review plugin update'};
 assert.equal(model.protectionState({...base,updates}).updates.engines[0].update_available,true);
 assert.throws(()=>model.protectionState({...base,updates:{...updates,issues:'healthy'}}));
 assert.throws(()=>model.protectionState({...base,updates:{...updates,engines:[{name:'falco',installed:'run command',latest:null,update_available:false}]}}));
});


test('overview priorities ignore stale diagnostic search, cap at three and preserve scans',()=>{
 const rows=['low','critical','medium','high'].map((severity,i)=>({check_id:'security.item'+i,status:'attention',severity,summary:'Example'}));
 const original=JSON.stringify(rows);
 assert.deepEqual(model.overviewFindings(rows,[]).map(c=>c.severity),['critical','high','medium']);
 assert.equal(model.overviewFindings(rows,['security.item1']).length,3);
 assert.equal(JSON.stringify(rows),original);
 assert.equal(model.overviewFindings([{...rows[0],status:'pass'}],[]).length,0);
});
test('overview health never treats missing, stopped, degraded or stale data as healthy',()=>{
 const unknown=model.overviewHealth(null,null);
 assert.ok(unknown.every(c=>!c.warning && c.value==="Not verified"));
 assert.ok(unknown.every(c=>!c.detail.includes("is off")));
 const capability={scanner:{ready:true,signatures_age_hours:2},updates:{automatic:true,issues:[]}};
 const healthy=model.overviewHealth(capability,{monitoring:true,state:'monitoring'});
 assert.ok(healthy.every(c=>!c.warning));
 assert.ok(model.overviewHealth(capability,{monitoring:true,state:'degraded'})[0].warning);
 assert.ok(model.overviewHealth({...capability,scanner:{ready:true,signatures_age_hours:30}},{monitoring:false,state:'stopped'})[1].warning);
 assert.ok(model.overviewHealth({...capability,updates:{automatic:true,issues:['failed']}},null)[2].warning);
});

test('security view retains vulnerable old Go alongside patched active Go and zero updates',()=>{
 const items=[{name:'go',source:'mise',installed:'1.26.10',active:true,available:null,advisories:[]},
 {name:'go',source:'mise',installed:'1.26.9',active:false,available:null,advisories:[{id:'GO-2026-6809'}],security_fixed_versions:['1.26.10']},
 {name:'go',source:'mise',installed:'1.27.2',active:false,available:null,advisories:[{id:'GO-2026-6809'}],security_fixed_versions:['1.27.3']}];
 assert.equal(model.appItems(items,'','Updates').length,0);
 assert.equal(model.appItems(items,'','Security').length,2);
 assert.equal(model.appItems(items,'','Installed').length,1);
 assert.equal(model.softwareSecurity(items).retained,2);
 assert.equal(model.softwareSecurity(items).configured,0);
 assert.match(model.securityVersionText(items[1]),/Retained/);
 assert.match(model.fixedReleaseText(items[2]),/1.27.3/);
});

test('large scan results keep passes, observations and coverage gaps distinct',()=>{
 const data=fixture();
 data.checks=Array.from({length:420},(_,i)=>({...data.checks[0],check_id:'test.control'+i,status:['pass','observed','unavailable','not_applicable','attention'][i%5]}));
 assert.equal(model.validate(data).checks.length,420);
 const counts=model.counts(data.checks);
 assert.equal(counts.passed,84);assert.equal(counts.facts,84);assert.equal(counts.notApplicable,84);assert.equal(counts.unavailable,168);assert.equal(counts.review,84);
 for(const id of ['sysctl.kernel.kptr_restrict','kconfig.fortify_source','cpu_mitigation.spectre_v2','service.sshd.service.nonewprivileges']) assert.equal(model.section(id),'Security');
 assert.equal(model.section('mount.tmp.noexec'),'Storage');assert.equal(model.section('listener.tcp.22'),'Network');
});
