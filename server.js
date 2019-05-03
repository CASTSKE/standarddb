var express =  require('express');
var app= express();
const Pg=require('pg').Pool;
var path=require('path')
var fs=require('fs')
var csv   = require('fast-csv');
var multer=require('multer');
var bodyParser = require('body-parser');

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));


app.set('view engine','ejs');
app.set('views',__dirname+'/views');
app.use(express.static(path.join(__dirname,'/src/public')))
app.use('/img',express.static(__dirname+'/src/public/img'))
app.use('/views',express.static(__dirname+'/views'))
var storage=multer.diskStorage({
    destination: function (req, file, callback) {
        callback(null, './uploads');
      },
      filename: function (req, file, callback) {
        callback(null, file.originalname);
      }
});
var csvWriter=require('csv-write-stream')
var writer = csvWriter({sendHeaders: false});

var upload = multer({ storage : storage}).single('userFile');


const pg = new Pg({ user: 'operator',
host: 'localhost',
database: 'standards',
password: 'CastAIP',
port: 2280,})
const pool =new Pg({ user: 'operator',
host: 'localhost',
database: 'standards',
password: 'CastAIP',
port:2280,},{multipleStatements:true})

pg.connect();
pool.connect();

var year=['1999','2000','2001','2002','2003','2004','2005','2006','2007','2008','2009','2010','2011','2012','2013','2014','2015','2016','2017','2018','2019']
var title=[]
var tech=[]
var lang=[]
var checkl=[]
var castl=[]
var sonl=[]

app.get("/",(req,res,next)=>{
    
    res.sendFile(__dirname+'/src/public/'+'index.html');
})
app.get("/index1",(req,res,next)=>{
    
    res.sendFile(__dirname+'/src/public/'+'public.html');
})

app.get("/index2",(req,res,next)=>{
    res.sendFile(__dirname+'/src/public/'+'comp.html');
})

app.get("/index3",(req,res,next)=>{
    var q="SELECT 'cwe',count(*) from cwe union select 'cve',count(*) from cvedata union select 'stig',count(*) from stig union select 'nist',count(*) from nist union select 'cisq',count(*) from cisq union select 'pci',count(*) from pci union select 'fortify',count(*) from fortify union select 'checkmarx',count(*) from checkmark union select 'cast',count(*) from castquality union select 'sonarqube',count(*) from sonarqube ;select count(NULLIF(cwe_sans_top_25_2009,'')) as a, count(NULLIF(cwe_sans_top_25_2010,'')) as b, count(NULLIF(owasp_top_10_2004,'')) as c, count(NULLIF(owasp_top_10_2007,'')) as d, count(NULLIF(owasp_top_10_2010,'')) as e, count(NULLIF(owasp_top_ten_2013,'')) as f, count(NULLIF(sei_cert_cpp_coding_standard_2016,'')) as g, count(NULLIF(the_cert_c_secure_coding_standard_2008,'')) as h, count(NULLIF(the_cert_oracle_secure_coding_standard_for_java_2011,'')) as i from cwe;SELECT cwe_id from cwe;SELECT cweid, COUNT (cweid)FROM checkmark GROUP BY cweid;SELECT count(cweid), cweid FROM (SELECT unnest(string_to_array(cwe_id, ',')) AS cweid FROM fortify) AS cweid GROUP BY cweid;"
    pool.query(q,(err,r)=>{
		//console.log(r[0].rows)
		//console.log(r[4].rows)
    res.render("analytics",{cq:r[0].rows[1].count,cmark:r[0].rows[5].count,cisq:r[0].rows[6].count,cve:r[0].rows[0].count,cwe:r[0].rows[2].count,fortify:r[0].rows[3].count,nist:r[0].rows[7].count,pci:r[0].rows[4].count,sonar:r[0].rows[8].count,stig:r[0].rows[9].count,count:r[1].rows[0],cweid:r[2].rows,cmcount:r[3].rows,forticount:r[4].rows})
	})
	
})

app.get("/sards",(req,res)=>{
	res.render('testcase');
    
})
app.get("/compare",(req,res,next)=>{
    var q="SELECT cwe_id from cwe;SELECT cweid, COUNT (cweid)FROM checkmark GROUP BY cweid;SELECT count(cweid), cweid FROM (SELECT unnest(string_to_array(cwe_id, ',')) AS cweid FROM fortify) AS cweid GROUP BY cweid;"
    pool.query(q,(err,r)=>{
		//console.log(r[0].rows)
		//console.log(r[4].rows)
    res.render("compare",{cweid:r[0].rows,cmcount:r[1].rows,forticount:r[2].rows})
	})
	
})
app.get("/login",(req,res,next)=>{
    var u=req.query.uname;
    var psw=req.query.psw;
    if(u == 'admin' && psw=='cast'){
        res.sendFile(__dirname+'/src/public/'+'serch.html');
    }
    else{
        res.sendFile(__dirname+'/src/public/'+'index.html');
    }
    
})

app.get("/searchall",(req,res)=>{
    var n=req.query.name;
    //name=name.replace(/CWE-/g,'')
    //name=name.replace(/CWE ID /g,'')
    var qc="select * from cvedata where name ilike '%"+n+"%' or description ilike '%"+n+"%' ; select * from cwe where cwe_id ilike '%"+n+"%' or extended_description ilike '%"+n+"%' or applicable_platforms ilike '%"+n+"%' or examples ilike '%"+n+"%' or observed_examples ilike '%"+n+"%' or taxonomy_mappings ilike '%"+n+"%' ; select * from fortify where title ilike '%"+n+"%' or technology ilike '%"+n+"%' or abstract ilike '%"+n+"%' or explanation ilike '%"+n+"%';"
    pool.query(qc,(err,r)=>{
       res.render('search.ejs',{data:r[0].rows,cwe:r[1].rows,forti:r[2].rows,x:n})
    })
  
})

//------competition-------------------------------------

app.get("/fortify",(req,res,next)=>{
     var x="ALL"
	 pool.query("select * from fortify",(err,r)=>{
        var i;
        var l=[]
        var m=[]
    for (i = 0; i < r.rows.length-1; i++) {
       l.push(r.rows[i].technology);
       text =r.rows[i].title;
       //console.log(text)
       if(text.indexOf(":")){
       t=text.substring(0,text.indexOf(":"));
       m.push(t);
        }
     else{
       m.push(text);
     }       
    }

    tech = Array.from(new Set(l))        
    title = Array.from(new Set(m))
  
    res.render('fortify',{forti:r.rows,tech:tech,title:title,x:x});
})
})
//-------checkmarks---------------------

app.get("/checkmark",(req,res,next)=>{
    pool.query("select * from checkmark;SELECT language FROM checkmark group by language;",(err,r)=>{
        checkl=r[1].rows
		//console.log(checkl)
		res.render('checkmark',{data:r[0].rows,lang:checkl,x:null});
    })
})

app.get("/checkid",(req,res,next)=>{
    checkl=checkl
	var id=req.query.name
    var q="select * from checkmark where language ilike '%"+id+"%' or packagename ilike '%"+id+"%' or queryname ilike '%"+id+"%' or cweid = '"+id+"'"
    pool.query(q,(err,r)=>{
        res.render('checkmark',{data:r.rows,lang:checkl,x:id});
    })
})



//--------------------------cast standard----------------
app.get("/castquality",(req,res,next)=>{
    pool.query("select * from castquality;SELECT technology FROM castquality group by technology;",(err,r)=>{
        castl=r[1].rows
		res.render('castqs',{data:r[0].rows,lang:castl,x:null})
    })
})

app.get("/castqs",(req,res,next)=>{
	castl=castl
    var id=req.query.name
    var q="select * from castquality where id ilike '%"+id+"%' or originalName ilike '%"+id+"%' or technology ilike '%"+id+"%' ;"
    pool.query(q,(err,r)=>{
        res.render('castqs',{data:r.rows,lang:castl,x:id})
    })
})

//-----------sonarqube-----------------------

app.get("/sonarqube",(req,res,next)=>{
    pool.query("select * from sonarqube;SELECT langname FROM sonarqube group by langname;",(err,r)=>{
        sonl=r[1].rows
		res.render('sonar.ejs',{data:r[0].rows,lang:sonl,x:null})
    })
})
app.get("/sonars",(req,res,next)=>{
    sonl=sonl
	var id=req.query.name
    var q="select * from sonarqube where key ilike '%"+id+"%' or htmldesc ilike '%"+id+"%' or name ilike '%"+id+"%';"
    pool.query(q,(err,r)=>{
        res.render('sonar.ejs',{data:r.rows,lang:sonl,x:id})
    })
})
app.get("/sonarid",(req,res,next)=>{
    var id=req.query.name
    var q="select * from sonarqube where key='"+id+"';"
    pool.query(q,(err,r)=>{
        res.render('sonarid.ejs',{data:r.rows,x:null})
    })
})

//----------------------------------------------------------------------------cve-----------------------------
app.get("/cvesearch",(req,res,next)=>{
    var q="select * from cvedata order by name desc;"
    pool.query(q,(err,r)=>{


            var i;
            var l=[]
        for (i = 0; i < r.rows.length; i++) {
          text =r.rows[i].name.substring(4,8);
          l.push(text);
        }
        year = Array.from(new Set(l))        
		var x="ALL"
        res.render("cve.ejs",{cve:r.rows,year:year.sort(),x:x})
    })
    
})

 app.get('/cveyear',(req,res,next)=>{
    var y=req.query.y
    year=year
	//console.log(year)
    var q="select * from cvedata where name ilike '%"+y+"%';"
    pool.query(q,(err,r)=>{
        res.render("cve.ejs",{cve:r.rows,year:year.sort(),x:y})
    })
 })
 app.get('/cvetype',(req,res,next)=>{
    var t=req.query.t
    year=year
    var q="select * from cvedata where description ilike '%"+t+"%';"
    pool.query(q,(err,r)=>{
        res.render("cve.ejs",{cve:r.rows,year:year.sort(),x:t})
    })
})


 app.get('/search',(req,res,next)=>{
        var name=req.query.name;
        var q="select * from cvedata where name='"+name+"';"
        var q1="select * from cvedata where name ilike '%"+name+"%' union select * from cvedata where description ilike '%"+name+"%';"
       
        pool.query(q,(err,r)=>{
           
            var p=r.rows;
            
            if(p[0]==null){
				year=year
                pool.query(q1,(err,rp)=>{
                    if(rp.rows==null){
                        res.send("Error search entry does not exists!")
                      }
                    else{  
                        res.render("cve.ejs",{cve:rp.rows,year:year.sort(),x:name})
                } })
            }
            else{
            var ref=p[0].reference
            if(ref !=null){
             ref=ref.split("|")
            }
            var comment=p[0].comments
            if(comment!=null){
            comment=comment.split("|")
            }
			var cwe=p[0].cwe;		
			if(cwe!=null){
				cwe=cwe.split(",")
			}
            res.render('cveid.ejs',{kk:r.rows,ref:ref,com:comment,cwe:cwe})
        }
        })
  })
   
  app.get('/cveadd',(req,res,next)=>{
    var id=req.query.id
    var t=req.query.tech
    var fw=req.query.frmwork
    var cwe=req.query.cwe
    var nist=req.query.nist
    var cs=req.query.cast
    var code=req.query.scode
	var code1=req.query.scode1
	var code2=req.query.scode2
    var rem=req.query.rems
    var rem1=req.query.rems1
    var rem2=req.query.rems2
    var pmc=req.query.pmc
    var rdc=req.query.rdc
    var cc=req.query.cc
    var links=req.query.links
    var d=Array.from([t,fw,nist,cwe,cs,code,code1,code2,rem,rem1,rem2,pmc,rdc,cc,links])
    //console.log(d)
    
    var q="update cvedata set technology=$1, frame_work=$2, nist=$3, cwer=$4, cast_support=$5, sample_code=$6,sample_code1=$7,sample_code2=$8, remediation=$9,remediation1=$10,remediation2=$11, cast_pm_comments=$12, rd_comments=$13, consultant_comments=$14, rem_links=$15 where name='"+id+"' returning *;"
    pool.query(q,d,(err,r)=>{
        if(err){
            console.log(err)
        }
        
        var m="Details have been updated"
        res.render('cvereview',{data:r.rows,id:id,m:m})  
    })
})

  app.get("/cvereview",(req,res,next)=>{
    var c=req.query.id
    //console.log(c)
    var q="select * from cvedata where name='"+c+"';"
    pool.query(q,(err,r)=>{
        m="Give your review"
        res.render('cvereview',{data:r.rows,id:c,m:m})

    })
})



//-----------------------------------------------cwe-------------------------


app.get('/cwe1',(req,res,next)=>{
  /* 
    */
	var x=req.query.id
	if(req.query.id=='ALL'){
    pool.query('select * from cwe order by cwe_id',(err,r)=>{
	var l=[]
        //console.log(r.rows.length)
        for (i = 0; i < r.rows.length; i++) {
          text =r.rows[i].applicable_platforms
		  if(text){
          s=text.match(/LANGUAGE NAME:([^:]*)/g)
          if(s!=null){
          for(j=0;j<s.length;j++){
              sx=s[j].replace(/LANGUAGE NAME:/g,'')
            l.push(sx)
            }}  
        }}
        lang = Array.from(new Set(l))        
        
	res.render("cwelist.ejs",{cwe:r.rows,lang:lang,x:x})
 
 })
    }
    else{
		//var q="select * from cwe where applicable_platforms like '%LANGUAGE NAME:"+req.query.id+":%' order by cwe_id"
        var q="select * from cwe where examples ilike '%LANGUAGE:"+req.query.id+":%' union select * from cwe where applicable_platforms ilike '%LANGUAGE NAME:"+req.query.id+":%' order by cwe_id"

		pool.query(q,(err,r)=>{
            res.render("cwelist.ejs",{cwe:r.rows,lang:lang,x:x})
        })    
    }
})

app.get('/cweid',(req,res,next)=>{
    var id=req.query.id;
	//id=id.replace(/CWE-/g,'')
	//id=id.replace(/CWE ID /g,'')
    id=id.match(/[0-9]+/g)
	var q="select * from cwe where cwe_id='"+id+"';"
    pool.query(q,(err,r)=>{
        var p=r.rows;
		if(p[0] == null){
			res.send("Search entry does not exists")
		}
		else{	res.render('cweid.ejs',{cwe:r.rows})
		}
	})
})



app.get('/cwesearch',(req,res,next)=>{
	var x=req.query.id
	//var q="select * from cwe where examples ilike '%"+req.query.id+"%' union select * from cwe where applicable_platforms ilike '%LANGUAGE NAME:"+req.query.id+":%' "
	var q="select * from cwe where examples ilike '%"+req.query.id+"%' union select * from cwe where applicable_platforms ilike '%LANGUAGE NAME:"+req.query.id+":%' union select * from cwe where cwe_id ilike '%"+req.query.id+"%' union select * from cwe where name ilike '%"+req.query.id+"%' order by cwe_id"

	lang=lang
		pool.query(q,(err,r)=>{
            res.render("cwelist.ejs",{cwe:r.rows,lang:lang,x:x})
        }) 
})

app.get('/cweadd',(req,res,next)=>{

    var id=req.query.id
    var t=req.query.tech
    var fw=req.query.frmwork
    var cwe=req.query.cwe
    var nist=req.query.nist
    var cs=req.query.cast
    var code=req.query.scode
	var code1=req.query.scode1
	var code2=req.query.scode2
    var rem=req.query.rems
    var rem1=req.query.rems1
    var rem2=req.query.rems2
    var pmc=req.query.pmc
    var rdc=req.query.rdc
    var cc=req.query.cc
    var links=req.query.links
    var d=Array.from([t,fw,nist,cwe,cs,code,code1,code2,rem,rem1,rem2,pmc,rdc,cc,links])
    //console.log(d)
    
    var q="update cwe set technology=$1, frame_work=$2, nist=$3, cve=$4, cast_support=$5, sample_code=$6,sample_code1=$7,sample_code2=$8, remediation=$9,remediation1=$10,remediation2=$11, cast_pm_comments=$12, rd_comments=$13, consultant_comments=$14, rem_links=$15 where cwe_id='"+id+"' returning *;"
    pool.query(q,d,(err,r)=>{
        if(err){
            console.log(err)
        }
        
        var m="Details have been updated"
        res.render('cwereview',{data:r.rows,id:id,m:m})  
    })
})

app.get("/cwereview",(req,res,next)=>{
    var c=req.query.id
    //console.log(c)
    var q="select * from cwe where cwe_id='"+c+"';"
    pool.query(q,(err,r)=>{
        m="Give your review"
        res.render('cwereview',{data:r.rows,id:c,m:m})

    })
})


//----------------------------------------------------------
//stig



app.get("/stig",(req,res,next)=>{
        
        var q1="select * from stig;"
        pool.query(q1,(err,r)=>{
          
            res.render('stig.ejs',{stig:r.rows})
        })
         
      })
app.get("/stigid",(req,res,next)=>{
        var id=req.query.id;
        var q2="select * from stig where vuln_id='"+id+"';"
        pool.query(q2,(err,r)=>{
            var p=r.rows;
			if(p[0]==null){
			res.send("search entry does not exists")
			}
			else{
			res.render('stigid.ejs',{stig:r.rows})
			}
		})
        
      }) 
app.get('/stigs',(req,res,next)=>{
	var id=req.query.id;
        var q2="select * from stig where vuln_id ilike '%"+id+"%' union select * from stig where title ilike '%"+id+"%' union select * from stig where description ilike '%"+id+"%';"
        pool.query(q2,(err,r)=>{
            
			res.render('stig.ejs',{stig:r.rows})
			
		})
        
})	  
	  process.on('uncaughtException', function (err) {
    console.log(err);
}); 

app.get("/stigreview",(req,res,next)=>{
    res.render('stigreview')
})

//--------------------------fortify------------------------------

app.get('/fortis',(req,res,next)=>{
    t=req.query.id
	tech=tech
    title=title
    var q= "select * from fortify where title ilike '%"+t+"%' or technology ilike '%"+t+"%' or abstract ilike '%"+t+"%' or explanation ilike '%"+t+"%' or cwe_id ilike '%"+t+"%';";
    pool.query(q,(err,r)=>{
        if(err){
            console.log(err)
        }
        res.render('fortify',{forti:r.rows,tech:tech,title:title,x:t})
    }) 
})

app.get('/fortid',(req,res,next)=>{
    name=req.query.id
    tc=req.query.tech
    var q= "select * from fortify where title='"+name+"' AND technology='"+tc+"'";
    pool.query(q,(err,r)=>{
        if(err){
            console.log(err)
        }
        res.render('fortiid',{forti:r.rows})
    }) 
})
  
app.get('/fortit',(req,res,next)=>{
	var x=req.query.id
    var q= "select * from fortify where  technology='"+req.query.id+"';";
    //console.log(req.query.id)
    
    tech=tech
    title=title
	pool.query(q,(err,r)=>{
        if(err){
            console.log(err)
        }
      
            res.render('fortify',{forti:r.rows,tech:tech,title:title,x:x})

    })
})    
app.get('/fortic',(req,res,next)=>{
	var x=req.query.id
    var q= "select * from fortify where  title ilike '%"+req.query.id+"%';";
    //console.log(req.query.id)
    tech=tech
    title=title
    pool.query(q,(err,r)=>{
        if(err){
            console.log(err)
        }
      
            res.render('fortify',{forti:r.rows,tech:tech,title:title,x:x})

    })
})    


//____________________________________CISQ__________________________________
app.get('/cisq',(req,res,next)=>{
    pool.query("select * from cisq",(err,r)=>{
        res.render('cisq',{cisq:r.rows})
    })
})
app.get('/cisqf',(req,res,next)=>{
    var id=req.query.name
	//console.log(id)
    var q="select * from cisq where descriptor ilike '%"+id+"%' union select * from cisq where remediation ilike '%"+id+"%'" 
    pool.query(q,(err,r)=>{
        res.render('cisq',{cisq:r.rows})
    })
})

app.get('/cisqs',(req,res,next)=>{
    var id=req.query.name
	//console.log(id)
    var q="select * from cisq where cisqid='"+id+"'" 
    pool.query(q,(err,r)=>{
        res.render('cisqid',{c:r.rows})
    })

})

app.get("/cisqreview",(req,res,next)=>{
    res.render('cisqreview')
})

//--------------------PCI-------------------------------

app.get('/pci',(req,res,next)=>{
    pool.query("select * from pci",(er,r)=>{
        res.render('pci',{p:r.rows})
    })
})
app.get('/pciid',(req,res,next)=>{
    var cid=req.query.name
    var q="select * from pci where cid='"+cid+"';"
    pool.query(q,(er,r)=>{
        res.render('pciid',{p:r.rows})
    }) 
})
app.get('/pcis',(req,res,next)=>{
	var id=req.query.name
	var q="select * from pci where control ilike '%"+id+"%' union select * from pci where domain ilike '%"+id+"';"
	 pool.query(q,(er,r)=>{
        res.render('pci',{p:r.rows})
    })
})
app.get("/pcireview",(req,res,next)=>{
    res.render('pcireview')
})

//--------------------------------------nist-----------------------

app.get('/nist',(req,res,next)=>{
    pool.query("select * from nist order by number",(er,r)=>{
        res.render('nist',{n:r.rows})
    })
})
app.get('/nistid',(req,res,next)=>{
    var id=req.query.name
    var q="select * from nist where number='"+id+"';"
    pool.query(q,(er,r)=>{
        res.render('nistid1',{n:r.rows})
    }) 
})
app.get("/nistreview",(req,res,next)=>{
    res.render('nistreview')
})
app.get("/nistsearch",(req,res,next)=>{
    var i=req.query.name
    //i=i.toUpperCase()
    var q="select * from nist where title ilike '%"+i+"%' union select * from nist where domain ilike '%"+i+"%' union select * from nist where enhancements ilike '%"+i+"%' "
    pool.query(q,(er,r)=>{
        res.render('nist',{n:r.rows})
    })
})

//--------import csv-----------------

app.post('/uploadnew',(req,res,next)=>{
    var cve=/cve/g  ;
    var cwe=/cwe/g;
    var stig=/stig/g;
    var pci=/pci/g;
    var nist=/nist/g;
    var fortify=/fortify/g;
      
    upload(req,res,function(err) {
        if(err) {
            return res.end("Error uploading file.");
        }
        if(cve.test(req.file.originalname)){
        console.log(req.file.originalname)

        //var q="insert into rules(name, status, description,reference,phase,votes,comments,created_at, cwe) select $1, $2, $3, $4, $5,$6,$7,$8,$9 WHERE NOT EXISTS (select name from rules where name= $1);"
        var q="insert into cve(name, status, description,reference,phase,votes,comments, created_at,cwe) select $1, $2, $3, $4, $5,$6,$7,$8,$9 WHERE NOT EXISTS (select name from cve where name= $1);"
        
        var p=__dirname+"/uploads/"+req.file.originalname;
         fs.createReadStream(p)
        .pipe(csv())
        .on('data', async function(data){
            var pa=/CVE-/i;
        if(pa.test(data[0])){
            var pat=/CWE-[0-9]+/g
            var pat1=/cwe-[0-9]+/g
            var m=data[2].match(pat)
            var m1=data[3].match(pat)
            var m2=data[3].match(pat1)
            var r='';
            if(m1!=null ){
                r=r.concat(m1.join())
            }
            if(m!=null){
                r=r.concat(m.join())
            }
            if(m2!=null){
                r=r.concat(m2.join())
            }
            data=data.concat(Date());   
            data=data.concat(r)
            
            pg.query(q,data, (err, r)=>{
               if(err){
                   //console.log(err)
               }
            })
        }
        })
        res.sendFile(__dirname+'/src/public/'+'serch.html');
        }

        if(cwe.test(req.file.originalname)){
            console.log("cwe: ",req.file.originalname)
            var p=__dirname+"/uploads/"+req.file.originalname;
            count= fs.createReadStream(p)
            .pipe(csv())
            .on('data', async function(data){
                data=data.concat(Date());
                var id=data[0] 
                var q2="insert into cwe(cwe_id, Name, Weakness_Abstraction,	Status,	Description, Extended_Description,	Related_Weaknesses, Weakness_Ordinalities,	Applicable_Platforms, Background_Details, Alternate_Terms, Modes_Of_Introduction, Exploitation_Factors,	Likelihood_of_Exploit,	Common_Consequences, Detection_Methods,	Potential_Mitigations, Observed_Examples, Functional_Areas, Affected_Resources, Taxonomy_Mappings, Related_Attack_Patterns, Notes, created_at) select $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24 WHERE NOT EXISTS (select cwe_id from cwe where cwe_id= $1);"
                //var q2="UPDATE cwe SET examples=$2 WHERE cwe.cwe_id=$1;"
                var a=/[0-9]+/g;
                if(a.test(id)){
                pg.query(q2,data,(err, r)=>{
                    if(err){
                    console.log(err)        
                    }
                })
                }
            })
            res.sendFile(__dirname+'/src/public/'+'serch.html'); 
        }

        if(fortify.test(req.file.originalname)){
            console.log(req.file.originalname)
            var q="insert into fortify(Title,	Abstract, Explanation, Example, Reference,	Technology,	Owasp,	Stig, Nist, CWE, PCI,	Technical_Guidelines, DISA,	FIPS, GDPR, WASC, cwe_id) select $1, $2, $3, $4, $5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17 WHERE NOT EXISTS (select title from fortify where title= $1 AND technology= $6 );"
            var p=__dirname+"/uploads/"+req.file.originalname;
            count= fs.createReadStream(p)
            .pipe(csv())
            .on('data', async function(data){
                var pat=/CWE ID [0-9]+/g
                var m=data[9].match(pat)
                var r='';
                if(m!=null ){
                    r=r.concat(m.join())
                }
                data=data.concat(r)
                pg.query(q, data,(err, r)=>{
                    if(err){
                        console.log(err)
                    } 
                })
                })
            res.sendFile(__dirname+'/src/public/'+'serch.html'); 
        }
        if(stig.test(req.file.originalname)){
            console.log(req.file.originalname)
            var q="INSERT INTO stig(vuln_id, rule_id, group1, version, severity, title, description, diacap, rmf, cci, check_id, check_text, fix_id, fix_text, filename) select $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15 WHERE NOT EXISTS (select vuln_id from stig where vuln_id= $1);"
            var p=__dirname+"/uploads/"+req.file.originalname;
            count= fs.createReadStream(p)
            .pipe(csv())
            .on('data', async function(data){
                var id=data[0]
                if(/V-[0-9]+/g.test(id)){
                pg.query(q, data,(err, r)=>{
                    if(err){
                        console.log(err)
                    }
                })
                }
            })
            res.sendFile(__dirname+'/src/public/'+'serch.html'); 
           
        }

        if(pci.test(req.file.originalname)){
            console.log(req.file.originalname)
            var q="INSERT INTO pci(did, domain, rid, requirement, cid, control, test, guidance, pri_6, pri_3, castapplicable) select $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11 WHERE NOT EXISTS (select cid from pci where cid= $5);"
            var p=__dirname+"/uploads/"+req.file.originalname;
            count= fs.createReadStream(p)
            .pipe(csv())
            .on('data', async function(data){
                var id=data[4]
                if(/[0-9]+/g.test(id)){
                pg.query(q, data,(err, r)=>{
                    if(err){
                        console.log(err)
                    }
                })
                }
            })
            res.sendFile(__dirname+'/src/public/'+'serch.html'); 
           
        }

        if(nist.test(req.file.originalname)){
            console.log(req.file.originalname)
            var q="INSERT INTO nist(domain,	number,	title,priority,impact,instructions,guidance,enhancements) select $1,$2,$3,$4,$5,$6,$7,$8 WHERE NOT EXISTS (select number from nist where number= $2);"
            var p=__dirname+"/uploads/"+req.file.originalname;
            var c=0;
            count= fs.createReadStream(p)
            .pipe(csv())
            .on('data',function(data){
                c=c+1;
                
                pg.query(q, data,(err, r)=>{
                    if(err){
                        //console.log(err)
                    }
                })
                
            
            })
            res.sendFile(__dirname+'/src/public/'+'serch.html'); 
        }
        if(/cisq/g.test(req.file.originalname)){
            console.log(req.file.originalname)
            var q="INSERT INTO cisq(cisqid,	Descriptor,	Remediation) select $1,$2,$3 WHERE NOT EXISTS (select cisqid from cisq where cisqid= $1);"
            var p=__dirname+"/uploads/"+req.file.originalname;
           
            count= fs.createReadStream(p)
            .pipe(csv())
            .on('data',function(data){
                var id=data[0]
                if(/[0-9]+/g.test(data[0])){
                pg.query(q, data,(err, r)=>{
                    if(err){
                        //console.log(err)
                    }
                   
                })
                }
            })
            res.sendFile(__dirname+'/src/public/'+'serch.html'); 
        }
		if(/cast/g.test(req.file.originalname)){
            console.log("cast: ",req.file.originalname)
            var p=__dirname+"/uploads/"+req.file.originalname;
            var q="insert into castquality(id,	originalName,	technology,	tag,	standard) select $1,$2,$3,$4,$5 where not exists (select id from castquality where id=$1 and technology=$3 and tag=$4);"
            count= fs.createReadStream(p)
            .pipe(csv())
            .on('data',function(data){
                var id=data[0]
                if(/[0-9]+/g.test(data[0])){
                pg.query(q, data,(err, r)=>{
                    if(err){
                        //console.log(err)
                    }
                   
                })
                }
            })
            res.sendFile(__dirname+'/src/public/'+'serch.html'); 
        }
		 if(/checkmark/g.test(req.file.originalname)){
            console.log("checkmark: ",req.file.originalname)
            var p=__dirname+"/uploads/"+req.file.originalname;
            var q="insert into checkmark(language, packagename,	queryname, cweid) select $1,$2,$3,$4 where not exists (select language from checkmark where packagename=$2 and queryname=$3 );"
            count= fs.createReadStream(p)
            .pipe(csv())
            .on('data',function(data){
                var id=data[0]
                pg.query(q, data,(err, r)=>{
                    if(err){
                        console.log(err)
                    }
                   
                })
            })
            res.sendFile(__dirname+'/src/public/'+'serch.html'); 
        }
		if(/sonarqube/g.test(req.file.originalname)){
            console.log("sonarqube: ",req.file.originalname)
            var create=pg.query("create table if not exists sonarqube(createdAt text,	htmlDesc text,	key text,	lang text,	langName text,	mdDesc text,	name text,	params text,	severity text,	sysTags text,	type text)",(err,r)=>{
				 if(err){
                        console.log(err)
                    }
			})
			var p=__dirname+"/uploads/"+req.file.originalname;
			
            var q="insert into sonarqube(createdAt,	htmlDesc,	key,	lang,	langName,	mdDesc,	name,	params,	severity,	sysTags,	type) select $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11 where not exists (select key from sonarqube where key=$3 );"
            count= fs.createReadStream(p)
            .pipe(csv())
            .on('data',function(data){
                var id=data[0]
                if(id != 'createdAt'){
                pg.query(q, data,(err, r)=>{
                    if(err){
                        console.log(err)
                    }
                   
                })
            }
            })
            res.sendFile(__dirname+'/src/public/'+'serch.html'); 
        }
    })
})
//-----------SARDS------------------------------

app.get('/sardscwe', function(req, res){
    // console.log(info()+" clientes request.... ");
    var q = "select cwe from sards cwe group by cwe order by SUBSTRING(cwe FROM '([0-9]+)')::BIGINT ASC, cwe;";
    pool.query(q, function(err, result, fields){
        if(err){
            
            res.send(info()+": dbErr...");
        }
        else
        {
            //console.log(info()+" "+result);
            res.send(result.rows);
        }
    });
});

app.post("/sardsid",(req,res)=>{
    var id=req.body.id
    
    var q="select name from sards where name ilike '%"+id+"%';" 
    pool.query(q,(err,r)=>{
        res.send(r.rows)
    })
})
app.post("/sardscode",(req,res,next)=>{

    var id=req.body.id
    var q= "select * from sards where name='"+id+"';"
    pool.query(q,(err,r)=>{
        res.send(r.rows[0])
    }) 
})



  app.listen(2281,()=>console.log("running in localhost://2281"));