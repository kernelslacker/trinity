
BEGIN{
	debug=0
	curr_pos=0
	target_pos=t_pos
} 

/.*<recipeSet>.*/,/<\/recipeSet>/ { 
	stage=stage"\n"$0; 
	if ( $0 ~ /.*VARIANT.*debug.*/ ){
		#print "hello";
		debug=1;
		next
	}
	if ( $0 ~ /<\/recipeSet>/ ){ 
		if (debug == 1) {
			debug=0;
		}
		else{
			print stage;
		}
		stage="";
	} 
	curr_pos=curr_pos+1
	next
}
{
	print 
}
