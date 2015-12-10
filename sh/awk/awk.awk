#!/usr/bin/awk

# Author: chuhu@redhat.com
# Parse the taskfile with restraint support and param support

function execute(cmd){
	#system(cmd);
	while(cmd |getline l){
		line=line"\n"l;
	} 
	return line
}

function parse_equation(line,is_key){
	split(line,dest,"=");	
	if(is_key)
		return dest[1];
	return dest[2];
}

function parse_restraint(line,space){
	#dmeo="<fetch url="git://git.engineering.redhat.com/users/chuhu/kernel-tests.git?master#general/code-coverage/start""
	fetch_node=""
	if(match(line,/fetch_url/) != 0){
		url=parse_equation(line,0);
		fetch_start=space"<fetch url="
		fetch_end="/>"
		fetch_node=fetch_start""url""fetch_end
	}
	return fetch_node
}

function parse_taskparam(line,algn){
	ret=""
	if (match(line,/=/) != 0){
		key=parse_equation(line,1);	
		value=parse_equation(line,0);	
		ret=getparam(key,value,"\t\t\t\t\t"algn);
	}		
	return ret;
}

function match_equation(line){
	return 0;
}

function oparse_taskfile(filename,algn){
	param_content=""
	git_url=""
	while(getline var < filename){
		split(var,pr," ");
		len=length(pr)
		tname=pr[len];
		for(s=1;s<=len;s++){
			node=parse_restraint(pr[s],"\t\t\t\t"algn)
			#pc=match_equation(pr[s]);
			if(length(node)>0)
				giturl=node;
			else{
				pc=parse_taskparam(pr[s],algn);
				if(length(pc)>0)
					param_content=param_content"\n"pc;
			}
		}
		tc=gettask(tname,param_content,giturl,"\t\t\t"algn);
		if(length(tc)>0){
			task_content=task_content"\n"tc;
		}
		param_content="";
		giturl="";
	}
	return task_content;
}

function getparam(name,value,space){
	param=space"<param name=\""name"\""" value=\""value"\"/>"
	return param
}

function gettask(taskname,param,git,space){
	st=space"<task"
	stet=space"<task/>"
	et=space"</task>"
	pss=space"\t""<params>"
	pse=space"\t""</params>"
	seps=space"\t""<params/>"
	tasknode=st" name=\""taskname"\" role=\"STANDALONE\">"
	if(length(git)>0){
		tasknode=tasknode"\n"git
	}
	if(length(param))
		tasknode=tasknode"\n"pss""param"\n"pse"\n"et
	else
		tasknode=tasknode"\n"seps"\n"et

	return tasknode;
}

BEGIN {
	tag=e_tag
	reg=".*</"tag">.*"
	aligin="\t"
	if(tag == "recipe"){
		aligin=""
	}
	l_file=e_file
	l_cmd="cat "l_file;
	if(l_cmd == ""){
		l_cmd=e_cmd
	}
	tasks=oparse_taskfile(l_file, aligin)
}
{
	if( match($0, reg) > 0 ){
		print tasks
		print $0
		next
	}
}
{
	print $0	
}
