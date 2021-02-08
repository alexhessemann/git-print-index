// Documentation of git's index file format: https://git-scm.com/docs/index-format

#include <arpa/inet.h>
#include <assert.h>
#include <grp.h>
#include <openssl/sha.h>
#include <pwd.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

struct header {
	char signature[4];
	uint32_t version;
	uint32_t entry_count;
};

struct extension {
	char signature[4];
	uint32_t len;
};

struct entry {
	// ctime and mtime should be struct timespec as they correspond to stat(2) values.
	// However struct timespec { time_t tv_sec; long tv_nsec; } are 64-bit fields 
	int32_t ctime;
	int32_t ctime_ns;
	int32_t mtime;
	int32_t mtime_ns;
	uint32_t dev;
	uint32_t ino;
	uint32_t mode;
	uint32_t uid;
	uint32_t gid;
	uint32_t file_size;
	char sha1[20];
	uint16_t flags;
	char * file_name; // 62th byte in v2
	char * pad_bytes;
	// Added members
	size_t file_name_len;
	size_t pad_bytes_len;
};

struct tree {
	char *path;
	int entry_count;
	unsigned subtrees;
	char sha1[20];
	char *file_name;
};

struct ctx {
	FILE *file;
	// From the header
	uint32_t version;
	uint32_t entry_count;
};

// Should return the same as fstrchr( a_file, 0 )
// NOT compatible with a FIFO
size_t get_stringz_len( FILE *a_file )
{
	size_t len = 0;
	size_t part_len;
	long pos = ftell( a_file );
	char buffer[257];
	buffer[256] = 0;
	do {
		// Issue if file ends before a \0 is found.
		fread( buffer, 1, 256, a_file );
		part_len = strlen( buffer );
		len += part_len;
	} while (part_len == 256);

	fseek( a_file, pos, SEEK_SET );
	
	return len;
}

// Returns the length before finding c
size_t fstrchr( FILE *a_file, int c )
{
	size_t len = 0;
	size_t part_len;
	long pos = ftell( a_file );
	char buffer[256];
	do {
		// Issue if file ends before c is found.
		fread( buffer, 1, 256, a_file );
		char *result = memchr( buffer, c, 256 );
		part_len = result ? result - buffer : 256;
		len += part_len;
	} while (part_len == 256);

	fseek( a_file, pos, SEEK_SET );
	
	return len;
}

void print_hex_string( size_t a_len, const void *a_ptr )
{
	size_t len = a_len;
	const uint8_t *ptr = (const uint8_t *) a_ptr;
	while (len--) {
		printf( "%02X", *ptr++ );
	}
}

void pretty_read_tree( FILE * a_file, long a_endpos, int a_level, bool a_last, const char * tree_str )
{
	if (ftell( a_file ) >= a_endpos) {
		if (a_level > 0) {
			fprintf( stderr, "Incomplete tree\n" );
		} // else parsing finished
	} else {
		struct tree tree;
		size_t len;
		char *entry_count;
		char *subtrees;
		char *new_tree_str;

		len = get_stringz_len( a_file );
		tree.path = malloc( len + 1 );
		fread( tree.path, 1, len + 1, a_file );
		len = fstrchr( a_file, ' ' );
		entry_count = malloc( len + 2 );
		entry_count[len + 1] = 0;
		fread( entry_count, 1, len + 1, a_file );
		len = fstrchr( a_file, '\n' );
		subtrees = malloc( len + 2 );
		subtrees[len + 1] = 0;
		fread( subtrees, 1, len + 1, a_file );
		tree.entry_count = atoi( entry_count );
		tree.subtrees = atoi( subtrees );

		if (tree.entry_count >= 0) {
			fread( tree.sha1, 1, 20, a_file );
			print_hex_string( 20, tree.sha1 );
		} else {
			printf( "                                        " );
		}

		printf( "  %s", tree_str );
		if (a_level > 0) {
			if (a_last) {
				printf( "└─ " );
				new_tree_str = malloc( strlen( tree_str ) + 4 );
				sprintf( new_tree_str, "%s   ", tree_str );
			} else {
				printf( "├─ " );
				new_tree_str = malloc( strlen( tree_str ) + 6 ); // '│' uses 3 bytes
				sprintf( new_tree_str, "%s│  ", tree_str );
			}
		} else {
			new_tree_str = strdup( tree_str );
		}
		printf( "'%s', %d entries\n", tree.path, tree.entry_count );

		if (tree.subtrees > 0) {
			for (int i=0; i < tree.subtrees - 1; i++) {
				pretty_read_tree( a_file, a_endpos, a_level + 1, false, new_tree_str );
			}
			pretty_read_tree( a_file, a_endpos, a_level + 1, true, new_tree_str );
		}
	}
}

void read_tree( FILE * a_file, long a_endpos )
{
	while (ftell( a_file ) < a_endpos ) {
		struct tree tree;
		size_t len = get_stringz_len( a_file );
		tree.path = malloc( len + 1 );
		fread( tree.path, 1, len + 1, a_file );
		printf( "Path: '%s'\n", tree.path );
		char *entry_count, *subtrees;
		// %m doesn't work on macOS (as of Xcode 11.6)
		len = fstrchr( a_file, ' ' );
		entry_count = malloc( len + 2 );
		entry_count[len + 1] = 0;
		fread( entry_count, 1, len + 1, a_file );
		len = fstrchr( a_file, '\n' );
		subtrees = malloc( len + 2 );
		subtrees[len + 1] = 0;
		fread( subtrees, 1, len + 1, a_file );
//		fscanf( a_file, "%m[0-9] %m[0-9]", &entry_count, &subtrees );
		tree.entry_count = atoi( entry_count );
		tree.subtrees = atoi( subtrees );
		printf( "Entry count: %d, subtrees: %u\n", tree.entry_count, tree.subtrees );
/*		int lf = fgetc( a_file );
		if (lf != '\n' ) {
			printf( "Unexpected byte\n" );
		}*/
		fread( tree.sha1, 1, 20, a_file );
		printf( "Object name: " );
		print_hex_string( 20, tree.sha1 );
		printf( "\n\n" );
//		printf( "\n%ld bytes remaining\n\n", endpos - ftell( a_file ) );
	}
	if (ftell( a_file ) > a_endpos) {
		printf( "We read too much\n" );
	}
}

// str must have enough space for 36/37 bytes:
// yyyy-mm-ddThh:mm:ss,nnnnnnnnn±hh:mm
// yyyy-mm-dd hh:mm:ss.nnnnnnnnn ±hh:mm
void time2str( char *a_str, int32_t a_sec, int32_t a_nsec )
{
	time_t time = (time_t) a_sec; // Extends to 64-bit
	struct tm *tm = localtime( &time ); // or gmtime
	char nanostr[12]; // Only 10 will be used if constraints are followed
	if (a_nsec < 0 || a_nsec >= 1000000000) {
		fprintf( stderr, "Invalid value nsec: %d\n", a_nsec );
	}
//	strftime( a_str, 36, "%FT%T,xxxxxxxxx%z", tm );
	strftime( a_str, 36, "%F %T.xxxxxxxxx %z", tm );
	sprintf( nanostr, "%09d",  a_nsec );
	memcpy( &a_str[20], nanostr, 9 );
}

void print_perm( char a_perm )
{
	printf( "%c%c%c", a_perm & 4 ? 'r' : '-', a_perm & 2 ? 'w' : '-', a_perm & 1 ? 'x' : '-' );
}

void print_flags( uint16_t a_flags )
{
	// Merge stages:
	// https://git-scm.com/book/en/v2/Git-Tools-Advanced-Merging
	// 0: no merge (?) '-'
	// 1: common ancestor 'c'
	// 2: ours 'o'
	// 3: theirs 't'
	char merge;
	switch ((a_flags >> 12) & 3) {
	case 0: merge = '-'; break;
	case 1: merge = 'c'; break;
	case 2: merge = 'o'; break;
	case 3: merge = 't'; break;
	}
	printf( "%c%c%c", a_flags & 0x8000 ? 'v' : '-', a_flags & 0x4000 ? 'x' : '-', merge );
}


int parse_index_entry( struct ctx * a_ctx, struct entry *entry )
{
	size_t result = fread( entry, 1, 62, a_ctx->file );
	if (result == 62) {
		entry->ctime = ntohl( entry->ctime );
		entry->ctime_ns = ntohl( entry->ctime_ns );
		entry->mtime = ntohl( entry->mtime );
		entry->mtime_ns = ntohl( entry->mtime_ns );
		entry->dev = ntohl( entry->dev );
		entry->ino = ntohl( entry->ino );
		entry->mode = ntohl( entry->mode );
		entry->uid = ntohl( entry->uid );
		entry->gid = ntohl( entry->gid );
		entry->file_size = ntohl( entry->file_size );
		entry->flags = ntohs( entry->flags );

		entry->file_name_len = get_stringz_len( a_ctx->file );
		entry->file_name = malloc( entry->file_name_len + 1 );
		if (entry->file_name) {
			result = fread( entry->file_name, 1, entry->file_name_len + 1, a_ctx->file );
			if (result == entry->file_name_len + 1) {
				if (ftell( a_ctx->file ) % 8 != 4) {
					entry->pad_bytes_len = 8 - ((ftell( a_ctx->file ) - 4) % 8);
					entry->pad_bytes = malloc( entry->pad_bytes_len ); // XXX: allocate and read with entry->file_name
					fread( entry->pad_bytes, 1, entry->pad_bytes_len, a_ctx->file );
				} else {
					entry->pad_bytes_len = 0; // It should be possible to do better…
				}
				result = 0;
			} else {
				perror( "Reading index entry file name" );
				result = 1;
			}
		} else {
			perror( "Allocating index entry file name" );
			result = 1;
		}

	} else {
		perror( "Reading index entry" );
		result = 1;
	}

	return result;
}


int parse_index_stat( struct ctx * a_ctx )
{
	int result;
	struct entry entry;
	for (int idx = 0; idx < a_ctx->entry_count; idx++) {
		result = parse_index_entry( a_ctx, &entry );

		char ctimestr[37];
		char mtimestr[37];
		time2str( ctimestr, entry.ctime, entry.ctime_ns );
		time2str( mtimestr, entry.mtime, entry.mtime_ns );

		const char *objtype = NULL;
		switch ((entry.mode >> 12) & 0x0F) {
		case 0x8: objtype = "regular file"; break;
		case 0xA: objtype = "symbolic link"; break;
		case 0xE: objtype = "gitlink"; break;
		}

		char objtype_c = '?';
		switch ((entry.mode >> 12) & 0x0F) {
		case 0x8: objtype_c = '-'; break;
		case 0xA: objtype_c = 'l'; break;
		case 0xE: objtype_c = 'g'; break;
		}

		struct passwd *user = getpwuid( entry.uid );
		struct group *group = getgrgid( entry.gid );

		int col_width[] = {17, 0};
		char dev_str[23];
		char flag_str[30];
		char ino_str[11];
		char *user_str = malloc( user ? strlen( user->pw_name ) + 14 : 14 );

		sprintf( dev_str, "%Xh/%ud", entry.dev, entry.dev );
		sprintf( flag_str, "%s%sstage %u", (entry.flags & 0x8000) ? "assume-valid," : "", (entry.flags & 0x4000) ? "extended," : "", (entry.flags >> 12) & 3 );
		sprintf( ino_str, "%u", entry.ino );
		sprintf( user_str, "(%u/%s)", entry.uid, user ? user->pw_name : "" );

		if (strlen( dev_str ) > col_width[0]) col_width[0] = strlen( dev_str );
		if (strlen( flag_str ) - 7 > col_width[1]) col_width[1] = strlen( flag_str ) - 7;
		if (strlen( ino_str ) > col_width[1]) col_width[1] = strlen( ino_str );
		if (strlen( user_str ) > col_width[1]) col_width[1] = strlen( user_str );

		printf( "Entry %u:\n", idx );
		printf( "\t  File: %s\n\t    ID: ", entry.file_name );
		print_hex_string( 20, entry.sha1 );
		printf( "\n\t  Size: %-*u %-*s %s\n", col_width[0], entry.file_size, col_width[1] + 7, flag_str, objtype );
		printf( "\tDevice: %-*s Inode: %-*s\n", col_width[0], dev_str, col_width[1], ino_str );
		printf( "\tAccess: (%04o/%c", entry.mode & 0x0FFF, objtype_c );
		print_perm( (entry.mode >> 6) & 7 );
		print_perm( (entry.mode >> 3) & 7 );
		print_perm( entry.mode & 7 );
		printf( ")   Uid: %-*s Gid: (%u/%s)\n", col_width[1], user_str, entry.gid, group ? group->gr_name : "" );
		printf( "\tModify: %s\n", mtimestr );
		printf( "\tChange: %s\n", ctimestr );

		if (entry.mode & 0xFFFF0000) {
			printf( "\tMode: 0x%08X\n", entry.mode );
		}
		if (entry.file_name_len != (entry.flags & 0x0FFF)) {
			printf("\tFilename length declared (%u) is different from the one computed (%zu)\n", entry.flags & 0x0FFF, entry.file_name_len );
		}
		printf( "\n" );
	}
	return result;
}

int parse_index_ls( struct ctx * a_ctx )
{
	int result;
	int idx;
	struct entry * entries = malloc( a_ctx->entry_count * sizeof( struct entry ) );
	struct entry * entry_p;

	struct passwd *user;
	struct group *group;
	char user_buffer[11];
	char group_buffer[11];
	const char *user_str;
	const char *group_str;

	int dev_width = 0;
	int inode_width = 0;
	int user_width = 0;
	int group_width = 0;
	int size_width = 0;

	for (idx = 0; idx < a_ctx->entry_count; idx++) {
		char buffer[11];
		entry_p = &entries[idx];
		result = parse_index_entry( a_ctx, entry_p );

		sprintf( buffer, "%u", entry_p->dev );
		if (strlen( buffer ) > dev_width) dev_width = strlen( buffer );

		sprintf( buffer, "%u", entry_p->ino );
		if (strlen( buffer ) > inode_width) inode_width = strlen( buffer );

		user = getpwuid( entry_p->uid );
		if (user) {
			user_str = user->pw_name;
		} else {
			sprintf( user_buffer, "%u", entry_p->uid );
			user_str = user_buffer;
		}
		if (strlen( user_str ) > user_width) user_width = strlen( user_str );

		group = getgrgid( entry_p->gid );
		if (group) {
			group_str = group->gr_name;
		} else {
			sprintf( group_buffer, "%u", entry_p->gid );
			group_str = group_buffer;
		}
		if (strlen( group_str ) > group_width) group_width = strlen( group_str );

		sprintf( buffer, "%u", entry_p->file_size );
		if (strlen( buffer ) > size_width) size_width = strlen( buffer );
	}

	for (idx = 0; idx < a_ctx->entry_count; idx++) {
		entry_p = &entries[idx];

		char ctimestr[37];
		char mtimestr[37];
		time2str( ctimestr, entry_p->ctime, entry_p->ctime_ns );
		time2str( mtimestr, entry_p->mtime, entry_p->mtime_ns );

		char objtype_c = '?';
		switch ((entry_p->mode >> 12) & 0x0F) {
		case 0x8: objtype_c = '-'; break;
		case 0xA: objtype_c = 'l'; break;
		case 0xE: objtype_c = 'g'; break;
		}

		user = getpwuid( entry_p->uid );
		group = getgrgid( entry_p->gid );
		if (user) {
			user_str = user->pw_name;
		} else {
			sprintf( user_buffer, "%u", entry_p->uid );
			user_str = user_buffer;
		}
		if (group) {
			group_str = group->gr_name;
		} else {
			sprintf( group_buffer, "%u", entry_p->gid );
			group_str = group_buffer;
		}

		printf( "%*u/%*u ", dev_width, entry_p->dev, inode_width, entry_p->ino );
		putchar( objtype_c );
		print_perm( (entry_p->mode >> 6) & 7 );
		print_perm( (entry_p->mode >> 3) & 7 );
		print_perm( entry_p->mode & 7 );
		putchar( ' ' );
		print_flags( entry_p->flags );
		printf( " %*s %-*s %*u %s %s ", user_width, user_str, group_width, group_str, size_width, entry_p->file_size, ctimestr, mtimestr );
		print_hex_string( 20, entry_p->sha1 );
		printf( " %s\n", entry_p->file_name );
	}
	
	putchar( '\n' );
	return result;
}


int parse_header( struct ctx * a_ctx )
{
	int result = 0;
	struct header header;
	fread( &header, 1, 12, a_ctx->file );
	a_ctx->version = ntohl( header.version );
	a_ctx->entry_count = ntohl( header.entry_count );

	if (memcmp( header.signature, "DIRC", 4 )) {
		fprintf( stderr, "Not a git index file.\n" );
		result = 1;
	} else {
		printf( "Version %u, entry count %u\n\n", a_ctx->version, a_ctx->entry_count );
	}

	return result;
}


int main( int argc, char * argv[] )
{
	struct ctx ctx;
	int result;

	if (argc < 2) {
		ctx.file = stdin;
		// We need to check if this is a redirection or a pipe. Pipes are not currently supported.
		struct stat statbuf;
		result = fstat( fileno( ctx.file ), &statbuf );
		if (result) {
			perror( "Stat'ing stdin" );
			return 1;
		} else if (!S_ISREG( statbuf.st_mode )) {
			fprintf( stderr, "stdin isn't a redirected regular file.\n" );
			return 1;
		}
		
	} else {
		ctx.file = fopen( argv[1], "r" );
		if (!ctx.file) {
			perror( "Opening file" );
			return 1;
		}
	}

	result = parse_header( &ctx );
	if (result) return 1;

#if LS_ENTRIES
	parse_index_ls( &ctx );
#else
	parse_index_stat( &ctx );
#endif

	struct extension ext;

	while (8 == fread( &ext, 1, 8, ctx.file )) {
		ext.len = ntohl( ext.len );
		long endpos = ftell( ctx.file ) + ext.len;
		switch (*((uint32_t*)ext.signature)) {
		case 0x45455254: // TREE
			printf( "Extension %.4s, length %u, content starting at offset %lu (0x%lX):\n", ext.signature, ext.len, ftell( ctx.file ), ftell( ctx.file ) );
#if PLAIN_TREE
			read_tree( ctx.file, endpos );
#else
			while (ftell( ctx.file ) < endpos ) {
				pretty_read_tree( ctx.file, endpos, 0, true, "" );
			}
			printf( "\n" );
#endif
			break;
		case 0x43554552: // REUC
			printf( "Extension %.4s, length %u, content starting at offset %lu (0x%lX):\n", ext.signature, ext.len, ftell( ctx.file ), ftell( ctx.file ) );
			printf( "Resolve undo, skipping\n" );
			fseek( ctx.file, ext.len, SEEK_CUR );
			break;
		case 0x6B6E696C: // link
			printf( "Extension %.4s, length %u, content starting at offset %lu (0x%lX):\n", ext.signature, ext.len, ftell( ctx.file ), ftell( ctx.file ) );
			printf( "Split index, skipping\n" );
			fseek( ctx.file, ext.len, SEEK_CUR );
			break;
		case 0x52544E55: // UNTR
			printf( "Extension %.4s, length %u, content starting at offset %lu (0x%lX):\n", ext.signature, ext.len, ftell( ctx.file ), ftell( ctx.file ) );
			printf( "Untracked cache, skipping\n" );
			fseek( ctx.file, ext.len, SEEK_CUR );
			break;
		case 0x4E4D5346: // FSMN
			printf( "Extension %.4s, length %u, content starting at offset %lu (0x%lX):\n", ext.signature, ext.len, ftell( ctx.file ), ftell( ctx.file ) );
			printf( "File system monitor cache, skipping\n" );
			fseek( ctx.file, ext.len, SEEK_CUR );
			break;
		case 0x45494F45: // EOIE
			printf( "Extension %.4s, length %u, content starting at offset %lu (0x%lX):\n", ext.signature, ext.len, ftell( ctx.file ), ftell( ctx.file ) );
			printf( "End of index entry, skipping\n" );
			fseek( ctx.file, ext.len, SEEK_CUR );
			break;
		case 0x544F4549: // IEOT
			printf( "Extension %.4s, length %u, content starting at offset %lu (0x%lX):\n", ext.signature, ext.len, ftell( ctx.file ), ftell( ctx.file ) );
			printf( "Index entry offset table, skipping\n" );
			fseek( ctx.file, ext.len, SEEK_CUR );
			break;
		default: {
				// Assume hash
				char hash[20];
				fseek( ctx.file, -8, SEEK_CUR );
				fread( hash, 1, 20, ctx.file );
				printf( "Hash checksum: " );
				print_hex_string( 20, hash );
				printf( "\n" );
			}
		}
	};

	return 0;
}
