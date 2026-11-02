const test = require('node:test');
const assert = require('node:assert/strict');
const { rebase, summary } = require('./manager_conflict.js');
test('rebase preserves untouched concurrent fields regardless of property order', () => {
    const original = {id:1,name:'old',kind:'login',username:'alice',notes:'',urls:[],fields:[{name:'region',secret:false,value:'old'}]};
    const latest = {...original,revision:2,username:'bob',fields:[{name:'region',secret:false,value:'new'},{name:'token',secret:true,value:null}]};
    const local = {...original,name:'my edit',password:null,fields:[{name:'region',value:'old',secret:false}],removeFields:[]};
    const merged = rebase(original,latest,local);
    assert.equal(merged.username,'bob'); assert.equal(merged.name,'my edit');
    assert.equal(merged.fields[0].value,'new'); assert.equal(merged.fields[1].value,null);
    assert.equal(merged.password,null);
});
test('conflict summaries exclude every secret value', () => {
    const original = {id:1,fields:[]};
    const latest = {id:1,fields:[{name:'token',secret:true,value:'hidden remote'}]};
    const local = {password:'hidden primary',fields:[{name:'token',secret:true,value:'hidden replacement'}],removeFields:[]};
    const text = summary(original,latest,local);
    for (const secret of ['hidden remote','hidden primary','hidden replacement']) assert.equal(text.includes(secret),false);
});
