-- test the shared hash

create function setme(key text, val text) returns void language plperl as $$

  my $key = shift;
  my $val = shift;
  $_SHARED{$key}= $val;

$$;

create function getme(key text) returns text language plperl as $$

  my $key = shift;
  return $_SHARED{$key};

$$;

select setme('ourkey','ourval');

select getme('ourkey');


