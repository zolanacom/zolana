import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import test from 'node:test';
const source=await readFile(new URL('./views.js',import.meta.url),'utf8');
const views=await import(`data:text/javascript;base64,${Buffer.from(source).toString('base64')}`);
const network={phase:'paused',source:'saved-feed',validator_count:0,last_observed_slot:81042,observed_at:null,genesis_hash:'G'.repeat(44),recorded_blocks:12,recorded_transactions:3,validators:[{identity:'A'.repeat(44),vote_account:'B'.repeat(44),last_vote:81041,delinquent:false}]};
test('untrusted public fields are escaped in table, detail, validator and network surfaces',()=>{
 const attack='\"><img src=x onerror=alert(1)>';
 const surfaces=[views.table([{slot:2,blockhash:attack,status:'finalized'}],'blocks'),views.detail('transaction',{signature:attack,slot:2}),views.validators({...network,validators:[{identity:attack,vote_account:attack}]}),views.build({...network,genesis_hash:attack}),views.status({...network,genesis_hash:attack})];
 for(const html of surfaces){assert.doesNotMatch(html,/<img|<script/);assert.match(html,/&lt;img/);}
});
test('missing history and absent validator identities explain partial coverage without inventing records',()=>{
 assert.match(views.detail('transaction',null),/partial coverage/);
 assert.match(views.table([],'blocks'),/No records/);
 assert.match(views.validatorDetail(network,'not-in-feed'),/absent from the currently connected feed/);
 assert.doesNotMatch(views.validators({...network,validators:[]}),/Validator 1/);
});
test('a block without a transaction vector remains renderable and public identifiers remain copyable',()=>{
 const html=views.detail('block',{slot:2,blockhash:'C'.repeat(44),parent_slot:1,status:'recorded'});
 assert.match(html,/No transactions are included/);assert.match(html,/data-copy=/);assert.match(html,/Retained payment transactions/);
});
test('transaction and validator details preserve source and privacy boundaries',()=>{
 assert.match(views.detail('transaction',{signature:'D'.repeat(88),slot:2,status:'finalized',execution:'success'}),/shielded payment amount/);
 assert.match(views.detail('transaction',{signature:'D'.repeat(88),slot:2,status:'recorded'}),/Saved public history/);
 assert.match(views.validatorDetail(network,'A'.repeat(44)),/operator independence/);
 assert.match(views.validators(network),/do not establish independent operators/);
});
test('browser delivery and release limits remain explicit without the retired local launcher',()=>{
 const html=views.build(network);assert.match(html,/browser wallet/i);assert.match(html,/href="\/wallet.html"/);assert.match(html,/no app download/i);assert.match(html,/remain release gates/);assert.match(html,/Post-quantum protection and Alpenglow are not live/);
 assert.doesNotMatch(html,/signed pilot packages|local wallet port|127\.0\.0\.1/i);
 assert.match(views.status(network),/does not establish independently operated consensus or production readiness/);
 assert.equal(views.date(null),'No observation');assert.equal(views.number(null),'—');
});
test('a fresh live observation is shown with its actual source and counts',()=>{
 const value=views.networkPresentation({...network,phase:'running',source:'live-feed',environment:'experimental-devnet'});
 assert.equal(value.live,true);assert.equal(value.phase,'Recent finalized activity');assert.equal(value.history,'Live finalized feed');assert.equal(value.environment,'Experimental devnet');
 assert.match(value.sourceNote,/12 indexed blocks/);assert.match(value.sourceNote,/81,042|—/);assert.match(value.sourceNote,/Refreshes automatically/);
});
test('paused, stale and failed-feed observations never keep a live-history label',()=>{
 for(const change of [{phase:'paused'},{phase:'unknown'},{phase:'running',feed_error:true}]){
  const value=views.networkPresentation({...network,source:'live-feed',...change});
  assert.equal(value.live,false);assert.equal(value.history,'Saved history');assert.match(value.sourceNote,/not a live feed/);assert.doesNotMatch(value.sourceNote,/Refreshes automatically/);
 }
 assert.equal(views.networkPresentation({...network,phase:'paused'}).phase,'Feed paused');
});
test('an unavailable profile stays unknown rather than becoming a fabricated preparing chain',()=>{
 const value=views.networkPresentation({phase:'unknown',source:'not-connected',genesis_hash:null});
 assert.equal(value.phase,'Status unavailable');assert.equal(value.environment,'Not connected');assert.equal(value.history,'Not connected');assert.match(value.sourceNote,/No public history source/);assert.doesNotMatch(value.sourceNote,/0 indexed|live finalized/i);
 assert.equal(views.networkPresentation({phase:'preparing',source:'not-connected'}).phase,'Preparing devnet');
});
test('sample age and time without refresh expire live observations while preserving saved records',()=>{
 const live={...network,phase:'running',source:'live-feed',feed_sampled_at:100,history_tip:81042};
 assert.equal(views.ageObservation(live,4999,110),live);
 const stale=views.ageObservation(live,5000,110);
 assert.equal(stale.phase,'unknown');assert.equal(stale.source,'saved-feed');assert.equal(stale.observation_stale,true);
 assert.equal(stale.validators,live.validators);assert.equal(stale.recorded_blocks,live.recorded_blocks);assert.equal(stale.history_tip,81042);
 const display=views.networkPresentation(stale);assert.equal(display.live,false);assert.equal(display.phase,'Observation stale');assert.equal(display.history,'Saved history');assert.match(display.observationNote,/expired/);
 assert.equal(views.ageObservation(stale,30000,110),stale);
});
test('missing timestamps and a future client-relative sample never allow indefinite live labels',()=>{
 const live={...network,phase:'running',source:'live-feed'};
 assert.equal(views.ageObservation(live,14999,100),live);assert.equal(views.ageObservation(live,15000,100).phase,'unknown');
 const future={...live,feed_sampled_at:200};assert.equal(views.ageObservation(future,15000,100).phase,'unknown');
 for(const phase of ['paused','syncing'])assert.equal(views.ageObservation({...live,phase},15000,100).phase,'unknown');
 const unbound={phase:'unknown',source:'not-connected'};assert.equal(views.ageObservation(unbound,30000,100),unbound);
});
test('voting-account counts and badges describe the retained sample rather than active validators',()=>{
 const retained={...network,phase:'unknown',validator_count:999,validators:[...network.validators,{identity:'C'.repeat(44),vote_account:'D'.repeat(44),last_vote:81000,delinquent:true}]};
 const html=views.validators(retained);assert.match(html,/2 voting accounts in the last sample/);assert.match(html,/Voting in last sample/);assert.match(html,/Delinquent in last sample/);
 assert.doesNotMatch(html,/999|active validators|three co-located|>Observed voting<\/span>/);
 assert.match(views.validatorDetail(retained,'A'.repeat(44)),/Feed state when read/);
 assert.match(views.validators({...retained,source:'not-connected',validators:[]}),/Voting-account count unavailable/);
});
test('status distinguishes public feed evidence, expired samples and failures without claiming service health',()=>{
 const live={...network,phase:'running',source:'live-feed'};
 assert.match(views.status(live),/not a service-health check/);assert.doesNotMatch(views.status(live),/bound health source|three co-located/);
 const failed={...live,phase:'unknown',source:'saved-feed',feed_error:true};
 assert.match(views.status(failed),/public feed is unavailable/);assert.doesNotMatch(views.status(failed),/>Live finalized feed</);
 for(const html of [views.validators(live),views.status(live)]){
  assert.match(html,/data-network-phase/);assert.match(html,/data-network-history/);assert.match(html,/data-network-observation-note/);
 }
});
