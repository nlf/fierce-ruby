require 'rexml/document'

class Class
    alias_method :attr_reader_without_tracking, :attr_reader
    def attr_reader(*names)
        attr_readers.concat(names)
        attr_reader_without_tracking(*names)
    end
    def attr_readers
        @attr_readers ||= [ ]
    end
    alias_method :attr_writer_without_tracking, :attr_writer
    def attr_writer(*names)
        attr_writers.concat(names)
        attr_writer_without_tracking(*names)
    end
    def attr_writers
        @attr_writers ||= [ ]
    end
    alias_method :attr_accessor_without_tracking, :attr_accessor
    def attr_accessor(*names)
        attr_readers.concat(names)
        attr_writers.concat(names)
        attr_accessor_without_tracking(*names)
    end
end

class DomainScan
    attr_reader :domain, :ip, :startscan, :startscanstr, :nameservers, :arin, :zonetransfers,
                :wildcard, :bruteforce, :findmx, :whois, :reverselookup, :findnearby
    def initialize(ds)
        self.class.attr_readers.each do |attr|
            case "#{attr}"
            when "nameservers"
                ds.elements["nameservers"] ? @nameservers = Nameservers.new(ds.elements["nameservers"]) : nil 
            when "arin"
                ds.elements["arin"] ? @arin = Arin.new(ds.elements["arin"]) : nil
            when "zonetransfers"
                ds.elements["zonetransfers"] ? @zonetransfers = ZoneTransfers.new(ds.elements["zonetransfers"]) : nil
            when "wildcard"
                ds.elements["wildcard"] ? @wildcard = Wildcard.new(ds.elements["wildcard"]) : nil
            when "prefix"
                ds.elements["bruteforce"] ? @bruteforce = Prefix.new(ds.elements["bruteforce"]) : nil
            when "findmx"
                ds.elements["findmx"] ? @findmx = FindMX.new(ds.elements["findmx"]) : nil
            when "whois"
                ds.elements["whois"] ? @whois = Whois.new(ds.elements["whois"]) : nil
            when "reverselookup"
                ds.elements["reverselookup"] ? @reverselookup = ReverseLookup.new(ds.elements["reverselookup"]) : nil
            when "findnearby"
                ds.elements["findnearby"] ? @findnearby = FindNearby.new(ds.elements["findnearby"]) : nil
            else
                eval("@#{attr} = ds.attributes['#{attr}']")
            end     
        end
    end
end

class NameserverNode
    attr_reader :hostname, :ip, :type, :ttl
    def initialize(nsnode)
        self.class.attr_readers.each do |attr|
            eval("@#{attr} = nsnode.attributes['#{attr}']")
        end
    end
end

class Nameservers
    attr_reader :starttime, :starttimestr, :endtime, :endtimestr, :elapsedtime, :nodes
    def initialize(ns)
        self.class.attr_readers.each do |attr|
            if "#{attr}" == "nodes"
                @nodes = []
                ns.elements["node"] ? ns.elements.each("node") { |e| @nodes.push(NameserverNode.new(e)) } : nil
            else
                eval("@#{attr} = ns.attributes['#{attr}']")
            end
        end
    end
end

class ArinNetHandle
    attr_reader :iprange, :nethandle, :cust_name, :address, :city, :state_prov, :zip_code, 
                :country, :cidr, :net_type, :comment, :reg_date, :updated, :rtech_handle,
                :rtech_name, :rtech_phone, :rtech_email, :org_abuse_handle, :org_abuse_name,
                :org_abuse_phone, :org_abuse_email, :org_noc_handle, :org_noc_name,
                :org_noc_phone, :org_noc_email, :org_tech_handle, :org_tech_name,
                :org_tech_phone, :org_tech_email
    def initialize(annode)
        self.class.attr_readers.each do |attr|
            case "#{attr}"
            when "iprange", "nethandle"
                eval("@#{attr} = annode.attributes['#{attr}']")
            else
                eval("@#{attr} = annode.elements['#{attr}'].text")
            end
        end
    end
end

class Arin
    attr_reader :query, :starttime, :starttimestr, :endtime, :endtimestr, :elapsedtime, :net_handles
    def initialize(an)
        self.class.attr_readers.each do |attr|
            if "#{attr}" == "net_handles"
                @net_handles = []
                an.elements.each("net_handle") { |e| @net_handles.push(ArinNetHandle.new(e)) }
            else
                eval("@#{attr} = an.attributes['#{attr}']")
            end
        end
    end
end

class ZoneTransfers
    attr_reader :starttime, :starttimestr, :endtime, :endtimestr, :elapsedtime, :zts
    def initialize(zt)
        self.class.attr_readers.each do |attr|
            if "#{attr}" == "zts"
                @zts = []
                zt.elements.each("zonetransfer") { |e| @zts.push(ZoneTransfer.new(e)) }
            else
                eval("@#{attr} = zt.attributes['#{attr}']")
            end
        end
    end
end

class ZoneTransfer
    attr_reader :nameserver, :bool, :rawoutput, :nodes
    def initialize(zts)
        self.class.attr_readers.each do |attr|
            if "#{attr}" == "rawoutput"
                @rawoutput = zts.elements["rawoutput"].text
            elsif "#{attr}" == "nodes"
                @nodes = []
                zts.elements.each("nodes/node") { |e| @nodes.push(ZoneTransferNode.new(e)) }
            else
                eval("@#{attr} = zts.attributes['#{attr}']")
            end
        end
    end
end

class ZoneTransferNode
    attr_reader :ip, :hostname, :type, :ttl
    def initialize(ztnode)
        self.class.attr_readers.each do |attr|
            eval("@#{attr} = ztnode.attributes['#{attr}']")
        end
    end
end

class Wildcard
    attr_reader :starttime, :starttimestr, :endtime, :endtimestr, :elapsedtime, :nodes
    def initialize(wc)
        self.class.attr_readers.each do |attr|
            if "#{attr}" == "nodes"
                @nodes = []
                wc.elements.each("node") { |e| @nodes.push(WildcardNode.new(e)) }
            else
                eval("@#{attr} = wc.attributes['#{attr}']")
            end
        end
    end
end

class WildcardNode
    attr_reader :hostname, :ip
    def initialize(wcnode)
        self.class.attr_readers.each do |attr|
            eval("@#{attr} = wcnode.attributes['#{attr}']")
        end
    end
end

class Prefix
    attr_reader :starttime, :starttimestr, :endtime, :endtimestr, :elapsedtime, :nodes
    def initialize(pf)
        self.class.attr_readers.each do |attr|
            if "#{attr}" == "nodes"
                @nodes = []
                pf.elements.each("node") { |e| @nodes.push(PrefixNode.new(e)) }
            else
                eval("@#{attr} = pf.attributes['#{attr}']")
            end        
        end
    end
end

class PrefixNode
    attr_reader :ip, :hostname, :type, :ttl
    def initialize(pfnode)
        self.class.attr_readers.each do |attr|
            eval("@#{attr} = pfnode.attributes['#{attr}']")
        end
    end
end

class FindMX
    attr_reader :starttime, :starttimestr, :endtime, :endtimestr, :elapsed, :mxs
    def initialize(mx)
        self.class.attr_readers.each do |attr|
            if "#{attr}" == "mxs"
                @mxs = []
                mx.elements.each("mx") { |e| @mxs.push(MX.new(e)) }
            else
                eval("@#{attr} = mx.attributes['#{attr}']")
            end
        end
    end    
end

class MX
    attr_reader :preference, :exchange
    def initialize(mx)
        self.class.attr_readers.each do |attr|
            eval("@#{attr} = mx.attributes['#{attr}']")
        end
    end
end

class Whois
    attr_reader :starttime, :starttimestr, :endtime, :endtimestr, :elapsed, :ranges
    def initialize(wh)
        self.class.attr_readers.each do |attr|
            if "#{attr}" == "ranges"
                @ranges = []
                wh.elements.each("range") { |e| @ranges.push(WhoisRange.new(e)) }
            else
                eval("@#{attr} = wh.attributes['#{attr}']")
            end
        end
    end
end

class WhoisRange
    attr_reader :iprange, :nethandle
    def initialize(whrange)
        self.class.attr_readers.each do |attr|
            eval("@#{attr} = whrange.attributes['#{attr}']")
        end
    end
end

class ReverseLookupNode
    attr_reader :ip, :hostname, :type, :ttl
    def initialize(rlnode)
        self.class.attr_readers.each do |attr|
            eval("@#{attr} = rlnode.attributes['#{attr}']")
        end
    end
end

class ReverseLookup
    attr_reader :starttime, :starttimestr, :endtime, :endtimestr, :elapsedtime, :nodes
    def initialize(rl)
        self.class.attr_readers.each do |attr|
            if "#{attr}" == "nodes"
                @nodes = []
                rl.elements.each("node") { |e| @nodes.push(ReverseLookupNode.new(e)) }
            else
                eval("@#{attr} = rl.attributes['#{attr}']")
            end
        end
    end
end

class FindNearbyPtr
    attr_reader :ip, :hostname, :ptrdname
    def initialize(fnptr)
        self.class.attr_readers.each do |attr|
            eval("@#{attr} = fnptr.attributes['#{attr}']")
        end
    end
end

class FindNearby
    attr_reader :starttime, :starttimestr, :endtime, :endtimestr, :elapsedtime, :ptrs
    def initialize(fn)
        self.class.attr_readers.each do |attr|
            if "#{attr}" == "ptrs"
                @ptrs = []
                fn.elements.each("ptr") { |e| @ptrs.push(FindNearbyPtr.new(e)) }
            else
                eval("@#{attr} = fn.attributes['#{attr}']")
            end
        end
    end
end
