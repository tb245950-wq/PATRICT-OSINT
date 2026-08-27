import os
import json
from typing import Dict, Any, Optional, List

class GraphEngine:
    """
    Mesin Visualisasi Graf Relasi Interaktif Ultra-Modern (Obsidian / Cyberpunk Theme).
    Menggunakan HTML5 Canvas Force-Graph dengan partikel bercahaya, link pulse animation,
    dan glassmorphism HUD dashboard interaktif.
    """

    COLOR_PALETTE = {
        "target": {"color": "#EC4899", "glow": "rgba(236, 72, 153, 0.8)", "badge": "bg-pink-950 text-pink-300 border-pink-700"},
        "phone": {"color": "#06B6D4", "glow": "rgba(6, 182, 212, 0.8)", "badge": "bg-cyan-950 text-cyan-300 border-cyan-700"},
        "location": {"color": "#10B981", "glow": "rgba(16, 185, 129, 0.8)", "badge": "bg-emerald-950 text-emerald-300 border-emerald-700"},
        "whatsapp": {"color": "#22C55E", "glow": "rgba(34, 197, 94, 0.8)", "badge": "bg-green-950 text-green-300 border-green-700"},
        "email": {"color": "#F59E0B", "glow": "rgba(245, 158, 11, 0.8)", "badge": "bg-amber-950 text-amber-300 border-amber-700"},
        "social": {"color": "#A855F7", "glow": "rgba(168, 85, 247, 0.8)", "badge": "bg-purple-950 text-purple-300 border-purple-700"},
        "dorking": {"color": "#3B82F6", "glow": "rgba(59, 130, 246, 0.8)", "badge": "bg-blue-950 text-blue-300 border-blue-700"},
        "network": {"color": "#818CF8", "glow": "rgba(129, 140, 248, 0.8)", "badge": "bg-indigo-950 text-indigo-300 border-indigo-700"},
        "caller": {"color": "#FB7185", "glow": "rgba(251, 113, 133, 0.8)", "badge": "bg-rose-950 text-rose-300 border-rose-700"}
    }

    def __init__(self, output_dir: str = "./output"):
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)

    def generate_relationship_graph(self, target_phone: str, full_data: Dict[str, Any]) -> str:
        nodes: List[Dict[str, Any]] = []
        links: List[Dict[str, Any]] = []
        node_id_counter = 1

        # 1. Target Root Node
        target_id = f"node_{node_id_counter}"
        node_id_counter += 1
        nodes.append({
            "id": target_id,
            "name": target_phone,
            "val": 35,
            "category": "Target Utama",
            "group": "target",
            "color": self.COLOR_PALETTE["target"]["color"],
            "glow": self.COLOR_PALETTE["target"]["glow"],
            "icon": "🎯",
            "description": f"Nomor telepon target utama: {target_phone}",
            "details": {
                "Target": target_phone,
                "Status": "Analisis Aktif",
                "Total Modul": full_data.get("meta", {}).get("total_modules", 7)
            }
        })

        # 2. Operator & Provider Node
        phone_data = full_data.get("phone_osint", {}).get("data", {})
        if phone_data:
            carrier_name = phone_data.get("carrier", "")
            if carrier_name and carrier_name != "tidak_diketahui":
                c_id = f"node_{node_id_counter}"
                node_id_counter += 1
                nodes.append({
                    "id": c_id,
                    "name": f"Provider: {carrier_name}",
                    "val": 22,
                    "category": "Telekomunikasi",
                    "group": "phone",
                    "color": self.COLOR_PALETTE["phone"]["color"],
                    "glow": self.COLOR_PALETTE["phone"]["glow"],
                    "icon": "📡",
                    "description": f"Jaringan operator: {carrier_name} ({phone_data.get('type')})",
                    "details": {
                        "Operator": carrier_name,
                        "Prefix Resmi": phone_data.get("original_prefix_carrier", carrier_name),
                        "Jenis Nomor": phone_data.get("type", "Seluler"),
                        "Sumber Data": phone_data.get("carrier_source", "ITU-T Registry")
                    }
                })
                links.append({"source": target_id, "target": c_id, "label": "provider"})

        # 3. Location & HLR Node
        loc_data = full_data.get("location_osint", {}).get("data", {})
        if loc_data:
            hlr_city = loc_data.get("hlr_area", loc_data.get("location_name", "Indonesia"))
            coords = loc_data.get("coordinates", {})
            l_id = f"node_{node_id_counter}"
            node_id_counter += 1
            nodes.append({
                "id": l_id,
                "name": f"Area: {hlr_city}",
                "val": 24,
                "category": "Wilayah HLR",
                "group": "location",
                "color": self.COLOR_PALETTE["location"]["color"],
                "glow": self.COLOR_PALETTE["location"]["glow"],
                "icon": "📍",
                "description": f"Area HLR registrasi kartu: {hlr_city}",
                "details": {
                    "Wilayah": hlr_city,
                    "Provinsi": loc_data.get("province", "Indonesia"),
                    "Koordinat": f"{coords.get('lat')}, {coords.get('lon')}",
                    "Level Akurasi": loc_data.get("accuracy_level", "Regional City")
                }
            })
            links.append({"source": target_id, "target": l_id, "label": "hlr_area"})

        # 4. WhatsApp Node
        wa_data = full_data.get("whatsapp_osint", {}).get("data", {})
        if wa_data:
            wa_id = f"node_{node_id_counter}"
            node_id_counter += 1
            nodes.append({
                "id": wa_id,
                "name": "WhatsApp (Active)",
                "val": 22,
                "category": "Messaging",
                "group": "whatsapp",
                "color": self.COLOR_PALETTE["whatsapp"]["color"],
                "glow": self.COLOR_PALETTE["whatsapp"]["glow"],
                "icon": "💬",
                "description": f"Status WhatsApp: {wa_data.get('status')}",
                "url": wa_data.get("direct_chat_link"),
                "details": {
                    "WhatsApp ID": wa_data.get("whatsapp_id"),
                    "Status": wa_data.get("status"),
                    "Chat Link": wa_data.get("direct_chat_link")
                }
            })
            links.append({"source": target_id, "target": wa_id, "label": "messaging"})

        # 5. Caller ID / Directory Node
        caller_data = full_data.get("caller_id_osint", {}).get("data", {})
        if caller_data:
            owner_name = caller_data.get("owner_name")
            if owner_name:
                name_id = f"node_{node_id_counter}"
                node_id_counter += 1
                nodes.append({
                    "id": name_id,
                    "name": f"Nama: {owner_name}",
                    "val": 26,
                    "category": "Identitas",
                    "group": "caller",
                    "color": self.COLOR_PALETTE["caller"]["color"],
                    "glow": self.COLOR_PALETTE["caller"]["glow"],
                    "icon": "👤",
                    "description": f"Nama kontak publik: {owner_name}",
                    "details": {
                        "Nama Lengkap": owner_name,
                        "Sumber": caller_data.get("source", "Directory Registry")
                    }
                })
                links.append({"source": target_id, "target": name_id, "label": "identity"})

        # 6. Email Nodes
        email_data = full_data.get("email_osint", {}).get("data", {})
        emails = email_data.get("emails", []) if isinstance(email_data, dict) else (email_data if isinstance(email_data, list) else [])
        for em in emails:
            email_addr = em.get("email") if isinstance(em, dict) else str(em)
            if email_addr:
                em_id = f"node_{node_id_counter}"
                node_id_counter += 1
                nodes.append({
                    "id": em_id,
                    "name": email_addr,
                    "val": 18,
                    "category": "Email",
                    "group": "email",
                    "color": self.COLOR_PALETTE["email"]["color"],
                    "glow": self.COLOR_PALETTE["email"]["glow"],
                    "icon": "✉️",
                    "description": f"Alamat email terkait: {email_addr}",
                    "details": {
                        "Alamat Email": email_addr,
                        "Sumber": em.get("source", "OSINT Correlation") if isinstance(em, dict) else "OSINT",
                        "Valid MX": "Ya" if isinstance(em, dict) and em.get("mx_valid") else "Tidak"
                    }
                })
                links.append({"source": target_id, "target": em_id, "label": "linked_email"})

        # 7. Social Media Nodes
        social_data = full_data.get("social_osint", {}).get("data", {})
        accounts = social_data.get("accounts", []) if isinstance(social_data, dict) else (social_data if isinstance(social_data, list) else [])
        for acc in accounts[:12]:
            platform = acc.get("platform", "Social") if isinstance(acc, dict) else "Social"
            url = acc.get("url", "") if isinstance(acc, dict) else str(acc)
            icon = acc.get("icon", "🌐") if isinstance(acc, dict) else "🌐"
            s_id = f"node_{node_id_counter}"
            node_id_counter += 1
            nodes.append({
                "id": s_id,
                "name": f"{platform}",
                "val": 18,
                "category": "Media Sosial",
                "group": "social",
                "color": self.COLOR_PALETTE["social"]["color"],
                "glow": self.COLOR_PALETTE["social"]["glow"],
                "icon": icon,
                "url": url,
                "description": f"Profil {platform}: {url}",
                "details": {
                    "Platform": platform,
                    "Kategori": acc.get("category", "Social Media") if isinstance(acc, dict) else "Social",
                    "Tautan": url
                }
            })
            links.append({"source": target_id, "target": s_id, "label": "social_profile"})

        # 8. Dorking Findings Nodes
        dork_data = full_data.get("dorking_osint", {}).get("data", {})
        findings = dork_data.get("findings", []) if isinstance(dork_data, dict) else []
        for item in findings[:8]:
            title = item.get("title", "Web Mention")
            clean_title = (title[:20] + "...") if len(title) > 20 else title
            d_id = f"node_{node_id_counter}"
            node_id_counter += 1
            nodes.append({
                "id": d_id,
                "name": clean_title,
                "val": 16,
                "category": "Dorking",
                "group": "dorking",
                "color": self.COLOR_PALETTE["dorking"]["color"],
                "glow": self.COLOR_PALETTE["dorking"]["glow"],
                "icon": "🔍",
                "url": item.get("url"),
                "description": item.get("snippet", title),
                "details": {
                    "Judul": title,
                    "Kategori": item.get("category", "General"),
                    "Sumber Mesin": item.get("engine", "Search Engine"),
                    "URL": item.get("url")
                }
            })
            links.append({"source": target_id, "target": d_id, "label": "web_mention"})

        # 9. Network IP Node
        net_data = full_data.get("network_osint", {}).get("data", {})
        if net_data:
            pub_ip = net_data.get("public_ip", "")
            if pub_ip and pub_ip != "N/A":
                net_id = f"node_{node_id_counter}"
                node_id_counter += 1
                nodes.append({
                    "id": net_id,
                    "name": f"IP: {pub_ip}",
                    "val": 18,
                    "category": "Jaringan",
                    "group": "network",
                    "color": self.COLOR_PALETTE["network"]["color"],
                    "glow": self.COLOR_PALETTE["network"]["glow"],
                    "icon": "🌐",
                    "description": f"Public IP Presence: {pub_ip}",
                    "details": {
                        "IP Publik": pub_ip,
                        "DNS": ", ".join(net_data.get("dns_servers", [])),
                        "Gateway": net_data.get("gateway", "N/A")
                    }
                })
                links.append({"source": target_id, "target": net_id, "label": "network"})

        safe_phone = target_phone.replace("+", "").replace(" ", "_")
        graph_file = os.path.join(self.output_dir, f"graph_{safe_phone}.html")
        
        html_content = self._generate_html(target_phone, nodes, links)
        with open(graph_file, "w", encoding="utf-8") as f:
            f.write(html_content)

        return graph_file

    def _generate_html(self, target: str, nodes: List[Dict[str, Any]], links: List[Dict[str, Any]]) -> str:
        graph_data_json = json.dumps({"nodes": nodes, "links": links}, ensure_ascii=False)
        
        return f"""<!DOCTYPE html>
<html lang="id">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Obsidian Cyber Graph: {target}</title>
    <!-- Tailwind CSS -->
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet">
    <!-- Force Graph Engine (HTML5 Canvas + WebGL + Physics) -->
    <script src="https://unpkg.com/force-graph"></script>
    <style>
        body {{
            background-color: #0A0D14;
            background-image: 
                radial-gradient(circle at 50% 50%, rgba(139, 92, 246, 0.05) 0%, transparent 60%),
                radial-gradient(rgba(255, 255, 255, 0.06) 1px, transparent 1px);
            background-size: 100% 100%, 28px 28px;
            color: #E2E8F0;
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            margin: 0;
            overflow: hidden;
            user-select: none;
        }}
        .glass-panel {{
            background: rgba(15, 23, 42, 0.82);
            backdrop-filter: blur(16px);
            border: 1px solid rgba(255, 255, 255, 0.1);
        }}
        .glow-effect {{
            box-shadow: 0 0 25px rgba(139, 92, 246, 0.25);
        }}
        /* Smooth Scrollbar */
        ::-webkit-scrollbar {{ width: 4px; }}
        ::-webkit-scrollbar-track {{ background: transparent; }}
        ::-webkit-scrollbar-thumb {{ background: rgba(255, 255, 255, 0.2); border-radius: 4px; }}
    </style>
</head>
<body>

    <!-- Main Canvas Container -->
    <div id="graph-container" class="w-screen h-screen absolute inset-0 z-0"></div>

    <!-- Top-Left Obsidian HUD Panel -->
    <div class="fixed top-4 left-4 z-20 flex flex-col space-y-3 w-84 max-w-[calc(100vw-2rem)]">
        
        <!-- Header & Quick Search -->
        <div class="glass-panel rounded-2xl p-4 shadow-2xl space-y-3">
            <div class="flex items-center justify-between">
                <div class="flex items-center space-x-2">
                    <div class="w-3 h-3 rounded-full bg-pink-500 shadow-[0_0_10px_#ec4899] animate-pulse"></div>
                    <h1 class="text-xs font-extrabold tracking-widest text-transparent bg-clip-text bg-gradient-to-r from-pink-400 via-purple-400 to-cyan-400 font-mono">
                        PATRICT CYBER GRAPH
                    </h1>
                </div>
                <span class="text-[10px] px-2 py-0.5 rounded-full bg-gray-900 border border-gray-800 text-gray-400 font-mono">
                    <span id="node-count">{len(nodes)}</span> Nodes
                </span>
            </div>

            <!-- Search Bar -->
            <div class="relative">
                <i class="fa-solid fa-magnifying-glass absolute left-3 top-2.5 text-xs text-gray-500"></i>
                <input 
                    type="text" 
                    id="search-input" 
                    placeholder="Cari entitas, email, sosmed..." 
                    class="w-full bg-gray-950/90 border border-gray-800 focus:border-purple-500/60 rounded-xl pl-8 pr-3 py-1.5 text-xs text-gray-100 placeholder-gray-500 focus:outline-none transition font-mono"
                />
            </div>
        </div>

        <!-- Group Filters Legend -->
        <div class="glass-panel rounded-2xl p-4 shadow-2xl space-y-2.5">
            <div class="flex items-center justify-between text-[11px] font-semibold text-gray-400 uppercase tracking-wider">
                <span>Filter Kategori</span>
                <button id="btn-reset-filters" class="text-xs text-purple-400 hover:text-purple-300 font-mono">Show All</button>
            </div>
            <div class="flex flex-wrap gap-1.5" id="category-pills">
                <button data-group="target" class="filter-pill text-[11px] px-2.5 py-1 rounded-lg bg-pink-950/70 border border-pink-600/50 text-pink-300 hover:bg-pink-900/60 transition">
                    🎯 Target
                </button>
                <button data-group="phone" class="filter-pill text-[11px] px-2.5 py-1 rounded-lg bg-cyan-950/70 border border-cyan-600/50 text-cyan-300 hover:bg-cyan-900/60 transition">
                    📡 Provider
                </button>
                <button data-group="location" class="filter-pill text-[11px] px-2.5 py-1 rounded-lg bg-emerald-950/70 border border-emerald-600/50 text-emerald-300 hover:bg-emerald-900/60 transition">
                    📍 Lokasi HLR
                </button>
                <button data-group="whatsapp" class="filter-pill text-[11px] px-2.5 py-1 rounded-lg bg-green-950/70 border border-green-600/50 text-green-300 hover:bg-green-900/60 transition">
                    💬 WhatsApp
                </button>
                <button data-group="email" class="filter-pill text-[11px] px-2.5 py-1 rounded-lg bg-amber-950/70 border border-amber-600/50 text-amber-300 hover:bg-amber-900/60 transition">
                    ✉️ Email
                </button>
                <button data-group="social" class="filter-pill text-[11px] px-2.5 py-1 rounded-lg bg-purple-950/70 border border-purple-600/50 text-purple-300 hover:bg-purple-900/60 transition">
                    🌐 Sosmed
                </button>
                <button data-group="dorking" class="filter-pill text-[11px] px-2.5 py-1 rounded-lg bg-blue-950/70 border border-blue-600/50 text-blue-300 hover:bg-blue-900/60 transition">
                    🔍 Dorking
                </button>
            </div>
        </div>

    </div>

    <!-- Top-Right Action Controls -->
    <div class="fixed top-4 right-4 z-20 flex items-center space-x-2">
        <button id="btn-zoom-in" title="Zoom In" class="glass-panel w-9 h-9 rounded-xl flex items-center justify-center text-gray-300 hover:text-white hover:border-purple-500/40 transition">
            <i class="fa-solid fa-plus text-xs"></i>
        </button>
        <button id="btn-zoom-out" title="Zoom Out" class="glass-panel w-9 h-9 rounded-xl flex items-center justify-center text-gray-300 hover:text-white hover:border-purple-500/40 transition">
            <i class="fa-solid fa-minus text-xs"></i>
        </button>
        <button id="btn-recenter" title="Reset View & Center" class="glass-panel w-9 h-9 rounded-xl flex items-center justify-center text-gray-300 hover:text-white hover:border-purple-500/40 transition">
            <i class="fa-solid fa-crosshairs text-xs"></i>
        </button>
        <button id="btn-toggle-orbit" title="Auto Orbit (Camera Spin)" class="glass-panel px-3 h-9 rounded-xl flex items-center space-x-1.5 text-xs text-gray-300 hover:text-white hover:border-purple-500/40 font-mono transition">
            <i class="fa-solid fa-rotate text-purple-400 animate-spin" id="orbit-icon" style="animation-duration: 6s; display: none;"></i>
            <span id="orbit-btn-text">Auto Orbit</span>
        </button>
    </div>

    <!-- Slide-over Right Inspector Drawer (Node Details) -->
    <div id="inspector-drawer" class="fixed top-0 right-0 h-full w-96 max-w-full z-30 glass-panel border-l border-gray-800 shadow-2xl p-6 flex flex-col justify-between transform translate-x-full transition-transform duration-300 ease-out">
        <div class="space-y-4">
            <div class="flex items-center justify-between pb-3 border-b border-gray-800">
                <div class="flex items-center space-x-2">
                    <span id="drawer-icon" class="text-xl">🎯</span>
                    <span id="drawer-badge" class="text-[10px] font-mono px-2 py-0.5 rounded-full bg-purple-950 text-purple-300 border border-purple-700">KATEGORI</span>
                </div>
                <button id="btn-close-drawer" class="w-7 h-7 rounded-lg bg-gray-900 text-gray-400 hover:text-white flex items-center justify-center">
                    <i class="fa-solid fa-xmark text-xs"></i>
                </button>
            </div>

            <div>
                <h2 id="drawer-title" class="text-lg font-bold text-gray-100 font-mono break-all">Node Title</h2>
                <p id="drawer-desc" class="text-xs text-gray-400 mt-1 leading-relaxed">Description summary goes here...</p>
            </div>

            <!-- Key-Value Metadata Grid -->
            <div class="space-y-2 pt-2">
                <span class="text-[11px] font-semibold uppercase tracking-wider text-gray-500">Metadata Intelijen:</span>
                <div id="drawer-meta-list" class="space-y-2 max-h-64 overflow-y-auto pr-1"></div>
            </div>
        </div>

        <div id="drawer-action-container" class="pt-4 border-t border-gray-800">
            <a id="drawer-link-btn" href="#" target="_blank" class="w-full py-2 px-4 rounded-xl bg-gradient-to-r from-purple-600 to-pink-600 hover:from-purple-500 hover:to-pink-500 text-white text-xs font-semibold flex items-center justify-center space-x-2 shadow-lg shadow-purple-600/30 transition">
                <span>Buka Tautan Asli</span>
                <i class="fa-solid fa-arrow-up-right-from-square text-[10px]"></i>
            </a>
        </div>
    </div>

    <!-- JavaScript Graph Engine -->
    <script>
        const graphData = {graph_data_json};

        const highlightNodes = new Set();
        const highlightLinks = new Set();
        let hoverNode = null;
        let selectedNode = null;
        let isOrbiting = false;
        let angle = 0;
        let orbitInterval = null;

        const container = document.getElementById('graph-container');
        const Graph = ForceGraph()(container)
            .graphData(graphData)
            .nodeId('id')
            .nodeVal('val')
            .nodeLabel('name')
            .linkSource('source')
            .linkTarget('target')
            .linkWidth(link => highlightLinks.has(link) ? 2.5 : 1.2)
            .linkColor(link => highlightLinks.has(link) ? '#F472B6' : 'rgba(148, 163, 184, 0.2)')
            .linkDirectionalParticles(link => highlightLinks.has(link) ? 4 : 2)
            .linkDirectionalParticleWidth(link => highlightLinks.has(link) ? 3 : 1.8)
            .linkDirectionalParticleSpeed(0.006)
            .linkDirectionalParticleColor(link => highlightLinks.has(link) ? '#F472B6' : 'rgba(148, 163, 184, 0.6)')
            .onNodeHover(node => {{
                highlightNodes.clear();
                highlightLinks.clear();
                if (node) {{
                    highlightNodes.add(node);
                    (node.neighbors || []).forEach(neighbor => highlightNodes.add(neighbor));
                    (node.links || []).forEach(link => highlightLinks.add(link));
                }}
                hoverNode = node || null;
            }})
            .onNodeClick(node => {{
                selectedNode = node;
                openDrawer(node);
                Graph.centerAt(node.x, node.y, 800);
                Graph.zoom(2.2, 800);
            }})
            .onBackgroundClick(() => {{
                closeDrawer();
                selectedNode = null;
            }})
            .nodeCanvasObject((node, ctx, globalScale) => {{
                const isHighlighted = highlightNodes.has(node) || node === selectedNode;
                const isDimmed = (highlightNodes.size > 0 || selectedNode) && !isHighlighted;
                
                const baseSize = node.val || 18;
                const radius = baseSize / 2;

                ctx.save();
                ctx.globalAlpha = isDimmed ? 0.15 : 1.0;

                // 1. Glowing Halo Outer Ring
                if (isHighlighted || node.group === 'target') {{
                    ctx.beginPath();
                    ctx.arc(node.x, node.y, radius * 1.6, 0, 2 * Math.PI, false);
                    ctx.fillStyle = node.glow || 'rgba(236, 72, 153, 0.4)';
                    ctx.fill();
                }}

                // 2. Core Circle Body
                ctx.beginPath();
                ctx.arc(node.x, node.y, radius, 0, 2 * Math.PI, false);
                ctx.fillStyle = node.color || '#EC4899';
                ctx.fill();
                ctx.lineWidth = isHighlighted ? 2.5 : 1.5;
                ctx.strokeStyle = isHighlighted ? '#FFFFFF' : 'rgba(255,255,255,0.4)';
                ctx.stroke();

                // 3. Emoji Icon inside Circle
                if (node.icon) {{
                    ctx.font = `${{radius * 0.95}}px sans-serif`;
                    ctx.textAlign = 'center';
                    ctx.textBaseline = 'middle';
                    ctx.fillText(node.icon, node.x, node.y);
                }}

                // 4. Text Label with Dark Pill Background
                const label = node.name;
                const fontSize = Math.max(11 / globalScale, 3.5);
                ctx.font = `${{fontSize}}px Inter, -apple-system, sans-serif`;
                const textWidth = ctx.measureText(label).width;
                const bckgDimensions = [textWidth + 8, fontSize + 4];

                ctx.fillStyle = isHighlighted ? 'rgba(15, 23, 42, 0.95)' : 'rgba(10, 13, 20, 0.75)';
                ctx.fillRect(node.x - bckgDimensions[0] / 2, node.y + radius + 3, bckgDimensions[0], bckgDimensions[1]);

                ctx.textAlign = 'center';
                ctx.textBaseline = 'middle';
                ctx.fillStyle = isHighlighted ? '#F8FAFC' : '#94A3B8';
                ctx.fillText(label, node.x, node.y + radius + 3 + bckgDimensions[1] / 2);

                ctx.restore();
            }});

        // Precompute neighbors for fast highlighting
        graphData.links.forEach(link => {{
            const a = typeof link.source === 'object' ? link.source : graphData.nodes.find(n => n.id === link.source);
            const b = typeof link.target === 'object' ? link.target : graphData.nodes.find(n => n.id === link.target);
            if (a && b) {{
                !a.neighbors && (a.neighbors = []);
                !b.neighbors && (b.neighbors = []);
                a.neighbors.push(b);
                b.neighbors.push(a);

                !a.links && (a.links = []);
                !b.links && (b.links = []);
                a.links.push(link);
                b.links.push(link);
            }}
        }});

        // Adjust Physics Forces (Barnes-Hut repulsion)
        Graph.d3Force('charge').strength(-450);
        Graph.d3Force('link').distance(110);

        // Drawer Logic
        const drawer = document.getElementById('inspector-drawer');
        function openDrawer(node) {{
            document.getElementById('drawer-icon').innerText = node.icon || '🎯';
            document.getElementById('drawer-badge').innerText = node.category || 'ENTITAS';
            document.getElementById('drawer-title').innerText = node.name || 'Detail Node';
            document.getElementById('drawer-desc').innerText = node.description || '';

            const metaContainer = document.getElementById('drawer-meta-list');
            metaContainer.innerHTML = '';
            if (node.details) {{
                for (const [k, v] of Object.entries(node.details)) {{
                    const row = document.createElement('div');
                    row.className = 'p-2.5 rounded-xl bg-gray-900/90 border border-gray-800 text-xs';
                    row.innerHTML = `<span class="text-gray-500 text-[10px] uppercase font-mono block">${{k}}</span><span class="text-gray-200 font-semibold font-mono break-all">${{v}}</span>`;
                    metaContainer.appendChild(row);
                }}
            }}

            const linkBtn = document.getElementById('drawer-link-btn');
            if (node.url) {{
                linkBtn.href = node.url;
                linkBtn.parentElement.style.display = 'block';
            }} else {{
                linkBtn.parentElement.style.display = 'none';
            }}

            drawer.classList.remove('translate-x-full');
        }}

        function closeDrawer() {{
            drawer.classList.add('translate-x-full');
        }}
        document.getElementById('btn-close-drawer').addEventListener('click', closeDrawer);

        // Search Input
        document.getElementById('search-input').addEventListener('input', (e) => {{
            const val = e.target.value.toLowerCase().trim();
            if (!val) {{
                highlightNodes.clear();
                highlightLinks.clear();
                return;
            }}
            const match = graphData.nodes.find(n => n.name.toLowerCase().includes(val) || n.category.toLowerCase().includes(val));
            if (match) {{
                highlightNodes.clear();
                highlightNodes.add(match);
                (match.neighbors || []).forEach(nb => highlightNodes.add(nb));
                Graph.centerAt(match.x, match.y, 600);
                Graph.zoom(2.0, 600);
                openDrawer(match);
            }}
        }});

        // Filter Pills
        document.querySelectorAll('.filter-pill').forEach(btn => {{
            btn.addEventListener('click', () => {{
                const group = btn.getAttribute('data-group');
                const filteredNodes = graphData.nodes.filter(n => n.group === group || n.group === 'target');
                const nodeIds = new Set(filteredNodes.map(n => n.id));
                const filteredLinks = graphData.links.filter(l => nodeIds.has(l.source.id || l.source) && nodeIds.has(l.target.id || l.target));
                Graph.graphData({{ nodes: filteredNodes, links: filteredLinks }});
                document.getElementById('node-count').innerText = filteredNodes.length;
            }});
        }});

        document.getElementById('btn-reset-filters').addEventListener('click', () => {{
            Graph.graphData(graphData);
            document.getElementById('node-count').innerText = graphData.nodes.length;
        }});

        // View Controls
        document.getElementById('btn-zoom-in').addEventListener('click', () => {{
            Graph.zoom(Graph.zoom() * 1.4, 400);
        }});
        document.getElementById('btn-zoom-out').addEventListener('click', () => {{
            Graph.zoom(Graph.zoom() * 0.7, 400);
        }});
        document.getElementById('btn-recenter').addEventListener('click', () => {{
            Graph.zoomToFit(600, 40);
        }});

        // Auto Orbit Camera Toggle
        document.getElementById('btn-toggle-orbit').addEventListener('click', () => {{
            isOrbiting = !isOrbiting;
            const spinIcon = document.getElementById('orbit-icon');
            const btnText = document.getElementById('orbit-btn-text');
            if (isOrbiting) {{
                spinIcon.style.display = 'inline-block';
                btnText.innerText = 'Stop Orbit';
                orbitInterval = setInterval(() => {{
                    angle += Math.PI / 300;
                    const dist = 350;
                    Graph.cameraPosition && Graph.cameraPosition({{
                        x: dist * Math.sin(angle),
                        z: dist * Math.cos(angle)
                    }});
                }}, 30);
            }} else {{
                spinIcon.style.display = 'none';
                btnText.innerText = 'Auto Orbit';
                clearInterval(orbitInterval);
            }}
        }});

        // Auto Fit on Init
        setTimeout(() => {{
            Graph.zoomToFit(800, 50);
        }}, 600);
    </script>
</body>
</html>
"""
