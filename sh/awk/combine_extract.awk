# Usage: awk -f virt_xml.awk *.xml
BEGIN{
	job_start=0	
	white_board=0
	mail_cc=0 # <cc> </cc>
	curr_pos=0
	target_pos=t_pos
	if(target_pos == "")
		t_pos=0
}

/<job.*/, /<whiteboard.*/ {
	if ( job_start != 1 && $0 ~ /<job.*/ ){
		job_start = 1;	
		print $0
		next;
	}
	if (white_board != 1 && $0 ~ /<whiteboard.*/ ){
		white_board = 1;
		print $0
		next
	}
	if ( $0 ~ /<notify>/){
		if ( mail_cc != 1  ){
			print $0
			getline l
			print l
			while ( l !~ /<\/notify>/ ){
				getline l
				print l
			}
			mail_cc = 1
		}
	}
	next
}

/<notify>/, /<\/notify>/ {
	if ( mail_cc != 1  ){
		print $0
	}
	if ( $0 ~ /<\/notify>/ )
		mail_cc = 1
}


/<recipeSet>/, /<\/recipeSet>/{
	#print "#####################" curr_pos t_pos
	if (curr_pos == t_pos)
		print $0	
	if ( $0 ~ /<\/recipeSet>/ ){
		curr_pos=curr_pos+1
		if (curr_pos > t_pos){
			curr_pos=0
			nextfile		
		}
	}
}

END{
	print "</job>"	
}
