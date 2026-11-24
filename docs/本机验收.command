#!/usr/bin/perl
# macOS 自带 Perl。只向本机默认端口发请求，只认指南指定的演示站。
use strict;
use warnings;
use utf8;
use HTTP::Tiny;
use JSON::PP;
binmode STDOUT, ':encoding(UTF-8)';
binmode STDERR, ':encoding(UTF-8)';
$| = 1;
delete @ENV{qw(http_proxy HTTP_PROXY https_proxy HTTPS_PROXY all_proxy ALL_PROXY)};
my $http = HTTP::Tiny->new(timeout => 8, max_redirect => 0);
my $base = 'http://127.0.0.1:47600';
my $echo_off;
END { system('/bin/stty', 'echo') if $echo_off; }
$SIG{INT} = sub { exit 130 };
sub hidden_input {
    my ($hint) = @_;
    print "$hint\n";
    if (-t STDIN) {
        system('/bin/stty', '-echo') == 0 or die "无法隐藏输入\n";
        $echo_off = 1;
    }
    my $value = <STDIN> // '';
    if ($echo_off) { system('/bin/stty', 'echo'); $echo_off = 0; }
    print "\n";
    $value =~ s/[\r\n]+\z//;
    return $value;
}
print "请新建一个只允许「验收」标签的客户端，在 App 选择「仅本机」。\n";
my $token = hidden_input('粘贴该客户端令牌后按回车。输入不显示。');
die "令牌格式不符\n" unless $token =~ /\A[a-f0-9]{64}\z/;
sub request {
    my ($method, $path, $data, $code) = @_;
    my %opts = (headers => {authorization => "Bearer $token"});
    if (defined $data) {
        $opts{headers}{'content-type'} = 'application/json';
        $opts{content} = encode_json($data);
    }
    $opts{headers}{'x-auth-code'} = $code if defined $code;
    my $r = $http->request($method, $base . $path, \%opts);
    die "无法连接。请确认 App 已解锁、选择仅本机、端口为 47600。\n" if $r->{status} == 599;
    return ($r->{status}, eval { decode_json($r->{content}) } // {}, $r->{headers});
}
my ($status, $result) = request('POST', '/v1/search', {query=>'北极星验收'});
die "搜索失败。请核对客户端令牌和开放范围。\n" unless $status == 200;
my @found = grep { $_->{title} eq '北极星验收' && $_->{domain} eq 'demo.test' } @{$result->{results}};
die "请先按指南录入唯一一条带验收标签的北极星验收账号。\n" unless @found == 1;
print "找到演示条目，账号摘要为 $found[0]->{masked_account}。\n";
my ($s, $grant) = request('POST','/v1/requests',{item_ref=>$found[0]->{item_ref}, fields=>['password'], reason=>'核对指南中的演示密码'});
die "申请失败。请检查冷却时间或待处理申请。\n" unless $s == 200 && ($grant->{request_id}//'') =~ /\Areq_[a-f0-9]{32}\z/;
my $path = '/v1/requests/' . $grant->{request_id} . '/secret';
my $code = hidden_input('在 App 核对条目和密码字段，重新输入主密码，选「交给 AI」。把屏幕上的授权码输入此处。');
$code =~ s/-//g;
die "授权码格式不符\n" unless $code =~ /\A[0-9A-Za-z]{8}\z/;
my ($ok, $secret, $headers) = request('GET',$path,undef,$code);
die "未取得约定的演示密码。请重新申请并检查假数据。\n"
    unless $ok == 200 && $headers->{'cache-control'} eq 'no-store' && @{$secret->{fields}} == 1
    && $secret->{fields}[0]{name} eq 'password' && $secret->{fields}[0]{value} eq 'Fake-Demo-3189!';
my ($again, $terminal) = request('GET',$path,undef,$code);
die "重复兑换检查未通过\n" unless $again == 410 && $terminal->{state} eq 'redeemed' && !exists $terminal->{fields};
print "通过。已收到指定假密码，服务要求不缓存，同一码第二次取用被拒绝。\n";
