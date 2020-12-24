// +build !windows

package hostgw

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"time"

	"encoding/json"
	"sync"

	"github.com/golang/glog"
	"github.com/coreos/flannel/backend"
	"github.com/coreos/flannel/pkg/ip"
	"github.com/coreos/flannel/subnet"
	"github.com/vishvananda/netlink"
	"golang.org/x/net/context"
)

func init() {
	backend.Register("mcloud", New)
}

type MCloudBackend struct {
	sm       subnet.Manager
	extIface *backend.ExternalInterface
}

func New(sm subnet.Manager, extIface *backend.ExternalInterface) (backend.Backend, error) {
	if !extIface.ExtAddr.Equal(extIface.IfaceAddr) {
		return nil, fmt.Errorf("your PublicIP differs from interface IP, meaning that probably you're on a NAT, which is not supported by mcloud backend")
	}

	be := &MCloudBackend{
		sm:       sm,
		extIface: extIface,
	}
	return be, nil
}

func (be *MCloudBackend) RegisterNetwork(ctx context.Context, wg *sync.WaitGroup, config *subnet.Config) (backend.Network, error) {
	n := &backend.RouteNetwork{
		SimpleNetwork: backend.SimpleNetwork{
			ExtIface: be.extIface,
		},
		SM:          be.sm,
		BackendType: "mcloud",
		Mtu:         be.extIface.Iface.MTU,
		LinkIndex:   be.extIface.Iface.Index,
	}
	n.GetRoute = func(lease *subnet.Lease) []*netlink.Route {
		var cidrs []string
		err := json.Unmarshal(lease.Attrs.BackendData, &cidrs)
		if err != nil || len(cidrs) == 0 {
			return nil
		}
		var res []*netlink.Route

		for _, cidr := range cidrs {
			_, ipNet, err := net.ParseCIDR(cidr)
			if err != nil {
				return nil
			}
			res = append(res, &netlink.Route{
				Dst:       ipNet,
				Gw:        lease.Attrs.PublicIP.ToIP(),
				LinkIndex: n.LinkIndex,
			})
		}

		return res
	}

	cfg := struct {
		Token     string `json:"token"`
		ServerURL string `json:"serverURL"`
		Region    string `json:"region"`
		IDC       string `json:"idc"`
	}{}

	if len(config.Backend) > 0 {
		//"token": "e463937d15576af58ae7a7040807c018",
		//"serverURL": "http://10.72.220.155:30888"
		if err := json.Unmarshal(config.Backend, &cfg); err != nil {
			return nil, fmt.Errorf("error decoding backend config: %v", err)
		}
	}

	subnets, err := getSubnets(cfg.ServerURL, cfg.Token, "", "", be.extIface.ExtAddr.String())

	if err != nil {
		glog.Errorf("get subnets from ipamserver error %v", err)
		return nil, fmt.Errorf("error got subnet from ipam server: %v", err)
	}

	var sns []string

	for _, v := range subnets {
		sns = append(sns, v.SubnetCIDR)
	}

	rawMessage, err := json.Marshal(sns)
	if err != nil {
		return nil, fmt.Errorf("error encoding subnets: %v", err)
	}

	attrs := subnet.LeaseAttrs{
		PublicIP:    ip.FromIP(be.extIface.ExtAddr),
		BackendType: "mcloud",
		BackendData: rawMessage,
	}

	l, err := be.sm.AcquireLease(ctx, &attrs)
	switch err {
	case nil:
		n.SubnetLease = l

	case context.Canceled, context.DeadlineExceeded:
		return nil, err

	default:
		return nil, fmt.Errorf("failed to acquire lease: %v", err)
	}

	return n, nil
}

const defaultTimeOut = 10 * time.Second

type IpamHttpRequest struct {
	HostIP string `json:"hostIp"`
	IDC    string `json:"idc"`
	Region string `json:"region"`
}

type Response struct {
	Code    int32    `json:"code"`
	Message string   `json:"msg"`
	Data    []Subnet `json:"data"`
}

type Subnet struct {
	SubnetCIDR string `json:"network"`
}

func getSubnets(serverURL, token, region, idc, hostip string) ([]Subnet, error) {
	client := &http.Client{}

	ipamReq := IpamHttpRequest{
		HostIP: hostip,
		IDC:    idc,
		Region: region,
	}

	reqJson, err := json.Marshal(ipamReq)
	if err != nil {
		return []Subnet{}, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), defaultTimeOut)
	defer cancel()

	req, err := http.NewRequest("POST", serverURL+"/api/ipam/host-network", bytes.NewBuffer(reqJson))
	if err != nil {
		return []Subnet{}, err
	}
	req.Close = true
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("auth-token", token)
	req = req.WithContext(ctx)

	resp, err := client.Do(req)
	if err != nil {
		return []Subnet{}, err
	}

	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return []Subnet{}, err
	}

	res := &Response{}
	err = json.Unmarshal(body, res)
	if err != nil {
		return []Subnet{}, fmt.Errorf("unmarshal body failed:%+v, body: %+v\n", err, string(body))
	}

	if res.Data == nil || len(res.Data) == 0 {
		return []Subnet{}, fmt.Errorf("require %+v failed: %+v", ipamReq, string(body))
	}

	return res.Data, nil
}
