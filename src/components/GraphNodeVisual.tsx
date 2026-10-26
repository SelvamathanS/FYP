import React from 'react';
import { GraphNode } from '../types/threatGraph';

interface GraphNodeVisualProps {
  node: GraphNode;
  isSelected: boolean;
  isHovered: boolean;
  isFaded: boolean;
  isDark: boolean;
}

export const GraphNodeVisual: React.FC<GraphNodeVisualProps> = ({
  node,
  isSelected,
  isHovered,
  isFaded,
  isDark
}) => {
  const { x, y, label, status, name } = node;
  const isHealthy = status === 'HEALTHY' || status === 'SELF_HEALED' || status === 'APPROVED';
  const isCompromised = status === 'COMPROMISED' || status === 'UNMITIGATED';

  // 1. SOFTWARE / COMPUTER SYSTEM NODES (High-Precision Grid Card & Hardware Chassis)
  if (label === 'Software') {
    const w = 184;
    const h = 104;
    const rx = 6;
    const left = x - w / 2;
    const top = y - h / 2;

    const chassisBorder = isSelected 
      ? '#38bdf8' 
      : isCompromised 
        ? '#ef4444' 
        : node.status === 'SELF_HEALED'
          ? '#06b6d4'
          : isDark ? '#1e293b' : '#cbd5e1';

    const chassisBg = isCompromised
      ? isDark ? '#260a0a' : '#fef2f2'
      : node.status === 'SELF_HEALED'
        ? isDark ? '#05232a' : '#f0fdfa'
        : isDark ? '#0b1324' : '#ffffff';

    const headerBg = isCompromised
      ? isDark ? '#3b1010' : '#fee2e2'
      : node.status === 'SELF_HEALED'
        ? isDark ? '#083344' : '#e0f2fe'
        : isDark ? '#111c33' : '#f1f5f9';

    // Identify specific system role to render specialized hardware icon
    const isDB = name.toLowerCase().includes('db') || name.toLowerCase().includes('sql') || (node.application && node.application.toLowerCase().includes('database'));
    const isK8s = name.toLowerCase().includes('k8s') || name.toLowerCase().includes('kubernetes');
    const isDC = name.toLowerCase().includes('dc') || name.toLowerCase().includes('controller') || name.toLowerCase().includes('windows');
    const isPay = name.toLowerCase().includes('payment') || name.toLowerCase().includes('pay');
    const isScada = name.toLowerCase().includes('scada') || name.toLowerCase().includes('controller') || name.toLowerCase().includes('plc');
    const isExchange = name.toLowerCase().includes('exchange') || name.toLowerCase().includes('mail');

    // Canonical display texts with clean length limits for perfect visual balance
    const appRaw = node.application || (name.includes('07') ? 'Customer Database' : name.includes('14') ? 'Employee Management' : name.includes('21') ? 'Internal Analytics API' : 'Application Service');
    const appDisplay = appRaw.length > 21 ? appRaw.slice(0, 19) + '…' : appRaw;
    
    const techRaw = node.technology || (name.includes('07') ? 'PostgreSQL / SQL' : name.includes('14') ? 'Java / Spring Boot' : name.includes('21') ? 'Python / Flask' : 'Linux / Service');
    const techDisplay = techRaw.length > 21 ? techRaw.slice(0, 19) + '…' : techRaw;

    const hostDisplay = node.hostname || `COMP-${name.replace(/\D/g, '') || '01'}`;

    return (
      <g className="system-server-node select-none">
        {/* Invisible Hit-Target covering the entire system grid cell */}
        <rect
          x={left - 6}
          y={top - 6}
          width={w + 12}
          height={h + 12}
          fill="transparent"
          pointerEvents="all"
          className="cursor-pointer"
        />

        {/* Selection Aura */}
        {isSelected && !isFaded && (
          <rect
            x={left - 4}
            y={top - 4}
            width={w + 8}
            height={h + 8}
            rx={rx + 2}
            fill="none"
            stroke="#38bdf8"
            strokeWidth="2"
            strokeDasharray="5 3"
            opacity="0.95"
            style={{ pointerEvents: 'none' }}
          />
        )}

        {/* Hover Highlight Focus Ring */}
        {isHovered && !isSelected && !isFaded && (
          <rect
            x={left - 2}
            y={top - 2}
            width={w + 4}
            height={h + 4}
            rx={rx + 1}
            fill="none"
            stroke="#38bdf8"
            strokeWidth="1.5"
            opacity="0.85"
            style={{ pointerEvents: 'none' }}
          />
        )}

        {/* Compromised Alert Halo */}
        {isCompromised && !isFaded && (
          <rect
            x={left - 3}
            y={top - 3}
            width={w + 6}
            height={h + 6}
            rx={rx + 1}
            fill="none"
            stroke="#ef4444"
            strokeWidth="1.5"
            className="animate-pulse opacity-80"
            style={{ pointerEvents: 'none' }}
          />
        )}

        {/* Server Rack Ears (Mounting brackets on left and right edges) */}
        <path
          d={`M ${left - 4} ${top + 10} L ${left} ${top + 10} L ${left} ${top + h - 10} L ${left - 4} ${top + h - 10} Z`}
          fill={isDark ? '#1e293b' : '#cbd5e1'}
          stroke={chassisBorder}
          strokeWidth="1"
        />
        <circle cx={left - 2} cy={top + 14} r="1" fill={isDark ? '#64748b' : '#475569'} />
        <circle cx={left - 2} cy={top + h - 14} r="1" fill={isDark ? '#64748b' : '#475569'} />

        <path
          d={`M ${left + w} ${top + 10} L ${left + w + 4} ${top + 10} L ${left + w + 4} ${top + h - 10} L ${left + w} ${top + h - 10} Z`}
          fill={isDark ? '#1e293b' : '#cbd5e1'}
          stroke={chassisBorder}
          strokeWidth="1"
        />
        <circle cx={left + w + 2} cy={top + 14} r="1" fill={isDark ? '#64748b' : '#475569'} />
        <circle cx={left + w + 2} cy={top + h - 14} r="1" fill={isDark ? '#64748b' : '#475569'} />

        {/* Main Computer Card Body */}
        <rect
          x={left}
          y={top}
          width={w}
          height={h}
          rx={rx}
          fill={chassisBg}
          stroke={chassisBorder}
          strokeWidth={isSelected ? 2 : 1.2}
          className="transition-colors duration-200"
        />

        {/* Engineering Target Corner Brackets for Clean Grid Alignment */}
        <g stroke={isSelected ? '#38bdf8' : isCompromised ? '#ef4444' : isDark ? '#334155' : '#94a3b8'} strokeWidth="1.2" fill="none">
          <path d={`M ${left + 1} ${top + 8} L ${left + 1} ${top + 1} L ${left + 8} ${top + 1}`} />
          <path d={`M ${left + w - 8} ${top + 1} L ${left + w - 1} ${top + 1} L ${left + w - 1} ${top + 8}`} />
          <path d={`M ${left + 1} ${top + h - 8} L ${left + 1} ${top + h - 1} L ${left + 8} ${top + h - 1}`} />
          <path d={`M ${left + w - 8} ${top + h - 1} L ${left + w - 1} ${top + h - 1} L ${left + w - 1} ${top + h - 8}`} />
        </g>

        {/* --- GRID ROW 1: HEADER STRIP (System Name & LED Status) --- */}
        <rect
          x={left + 1}
          y={top + 1}
          width={w - 2}
          height={24}
          rx={rx - 1}
          fill={headerBg}
        />
        <line
          x1={left}
          y1={top + 25}
          x2={left + w}
          y2={top + 25}
          stroke={isDark ? '#1e293b' : '#e2e8f0'}
          strokeWidth="1"
        />

        {/* Power Status LED & Mini System Icon (x = left + 13) */}
        <circle
          cx={left + 13}
          cy={top + 13}
          r="3"
          fill={isCompromised ? '#ef4444' : node.status === 'SELF_HEALED' ? '#06b6d4' : '#10b981'}
          className={isCompromised ? 'animate-ping' : ''}
        />
        <circle
          cx={left + 13}
          cy={top + 13}
          r="2.5"
          fill={isCompromised ? '#ef4444' : node.status === 'SELF_HEALED' ? '#06b6d4' : '#10b981'}
        />

        {/* 1. Main Computer Title: e.g. COMPUTER 01, COMPUTER 07 */}
        <text
          x={left + 24}
          y={top + 16.5}
          fill={isFaded ? '#64748b' : isCompromised ? (isDark ? '#f87171' : '#dc2626') : (isDark ? '#38bdf8' : '#0369a1')}
          fontSize="11"
          fontWeight="800"
          fontFamily="ui-monospace, monospace"
          letterSpacing="0.04em"
          textAnchor="start"
        >
          {name.toUpperCase()}
        </text>

        {/* Top-Right Hostname Badge */}
        <text
          x={left + w - 12}
          y={top + 16}
          fill={isDark ? '#64748b' : '#94a3b8'}
          fontSize="8"
          fontWeight="700"
          fontFamily="ui-monospace, monospace"
          textAnchor="end"
        >
          {hostDisplay}
        </text>

        {/* --- GRID ROW 2: APPLICATION SPECIFICATION --- */}
        <text
          x={left + 12}
          y={top + 42}
          fontSize="7.5"
          fontWeight="800"
          fontFamily="ui-monospace, monospace"
          fill={isDark ? '#64748b' : '#64748b'}
          letterSpacing="0.05em"
        >
          APP:
        </text>
        <text
          x={left + 46}
          y={top + 42}
          fill={isFaded ? '#475569' : isDark ? '#f8fafc' : '#0f172a'}
          fontSize="9.5"
          fontWeight="600"
          fontFamily="Plus Jakarta Sans, -apple-system, BlinkMacSystemFont, sans-serif"
          textAnchor="start"
        >
          {appDisplay}
        </text>

        {/* --- GRID ROW 3: TECHNOLOGY STACK SPECIFICATION --- */}
        <text
          x={left + 12}
          y={top + 61}
          fontSize="7.5"
          fontWeight="800"
          fontFamily="ui-monospace, monospace"
          fill={isDark ? '#64748b' : '#64748b'}
          letterSpacing="0.05em"
        >
          STACK:
        </text>
        <text
          x={left + 46}
          y={top + 61}
          fill={isFaded ? '#334155' : isDark ? '#cbd5e1' : '#334155'}
          fontSize="8.5"
          fontFamily="ui-monospace, monospace"
          fontWeight="600"
          textAnchor="start"
        >
          {techDisplay}
        </text>

        {/* --- GRID ROW 4: STATUS BADGE & IP:PORT FOOTNOTE --- */}
        {/* 4. Live Health Status Badge: HEALTHY, COMPROMISED, SELF-HEALED */}
        <g transform={`translate(${left + 12}, ${top + 75})`}>
          <rect
            width="82"
            height="18"
            rx="3"
            fill={
              isCompromised 
                ? (isDark ? '#450a0a' : '#fee2e2') 
                : node.status === 'SELF_HEALED' 
                  ? (isDark ? '#083344' : '#cffafe')
                  : (isDark ? '#052e16' : '#dcfce7')
            }
            stroke={
              isCompromised 
                ? '#ef4444' 
                : node.status === 'SELF_HEALED' 
                  ? '#06b6d4'
                  : '#10b981'
            }
            strokeWidth="0.8"
          />
          <text
            x="41"
            y="12.5"
            textAnchor="middle"
            fontSize="8"
            fontWeight="800"
            fontFamily="ui-monospace, monospace"
            letterSpacing="0.03em"
            fill={
              isCompromised 
                ? (isDark ? '#fca5a5' : '#b91c1c') 
                : node.status === 'SELF_HEALED' 
                  ? (isDark ? '#67e8f9' : '#0e7490')
                  : (isDark ? '#86efac' : '#15803d')
            }
          >
            {isCompromised ? 'COMPROMISED' : node.status === 'SELF_HEALED' ? 'SELF-HEALED' : 'HEALTHY'}
          </text>
        </g>

        {/* 5. IP & Port Technical Footnote (Aligned to right edge) */}
        <text
          x={left + w - 12}
          y={top + 87.5}
          fill={isFaded ? '#334155' : isDark ? '#64748b' : '#64748b'}
          fontSize="8"
          fontFamily="ui-monospace, monospace"
          fontWeight="600"
          textAnchor="end"
          className="tabular-nums"
        >
          {node.ip ? `${node.ip}:${node.port || 80}` : ''}
        </text>
      </g>
    );
  }

  // 2. VULNERABILITY / CVE NODES (Bio-Cyber Threat Bug / Exploit Warning Badge)
  if (label === 'Vulnerability') {
    const r = 26;
    const isHealed = status === 'SELF_HEALED';
    const bgFill = isHealed
      ? isDark ? '#064e3b' : '#ecfdf5'
      : isDark ? '#450a0a' : '#fef2f2';
    const stroke = isHealed ? '#10b981' : '#ef4444';

    return (
      <g className="vulnerability-bug-node">
        {/* Generous Hit-Target covering bug badge and name label */}
        <circle
          cx={x}
          cy={y}
          r={34}
          fill="transparent"
          pointerEvents="all"
          className="cursor-pointer"
        />
        <rect
          x={x - 65}
          y={y - 26}
          width={130}
          height={75}
          fill="transparent"
          pointerEvents="all"
          className="cursor-pointer"
        />

        {/* Pulsing Breach Ring if Unmitigated */}
        {!isHealed && !isFaded && (
          <circle
            cx={x}
            cy={y}
            r={r + 8}
            fill="none"
            stroke="#ef4444"
            strokeWidth="1.5"
            className="animate-pulse opacity-70"
            style={{ pointerEvents: 'none' }}
          />
        )}

        {/* Selection Ring */}
        {isSelected && !isFaded && (
          <circle
            cx={x}
            cy={y}
            r={r + 7}
            fill="none"
            stroke="#38bdf8"
            strokeWidth="2"
            strokeDasharray="5 3"
            style={{ pointerEvents: 'none' }}
          />
        )}

        {/* Hover Highlight Focus Ring */}
        {isHovered && !isSelected && !isFaded && (
          <circle
            cx={x}
            cy={y}
            r={r + 4}
            fill="none"
            stroke={isHealed ? "#34d399" : "#f87171"}
            strokeWidth="1.5"
            opacity="0.85"
            style={{ pointerEvents: 'none' }}
          />
        )}

        {/* Warning Hazard Hexagon / Octagon Body */}
        <polygon
          points={`
            ${x - 24},${y - 10}
            ${x - 10},${y - 24}
            ${x + 10},${y - 24}
            ${x + 24},${y - 10}
            ${x + 24},${y + 10}
            ${x + 10},${y + 24}
            ${x - 10},${y + 24}
            ${x - 24},${y + 10}
          `}
          fill={bgFill}
          stroke={stroke}
          strokeWidth={isSelected ? 2.5 : 2}
        />

        {/* Inner Bug or Healed Shield Icon */}
        <g transform={`translate(${x - 12}, ${y - 12})`} style={{ pointerEvents: 'none' }}>
          {isHealed ? (
            /* Healed Shield with Checkmark */
            <g>
              <path
                d="M 12 2 L 21 6 V 13 C 21 18 12 22 12 22 C 12 22 3 18 3 13 V 6 Z"
                fill="#059669"
                stroke="#6ee7b7"
                strokeWidth="1.2"
              />
              <path
                d="M 7.5 12 L 10.5 15 L 16.5 9"
                fill="none"
                stroke="#ffffff"
                strokeWidth="2"
                strokeLinecap="round"
                strokeLinejoin="round"
              />
            </g>
          ) : (
            /* Cyber Threat Bug / Exploit Vector Icon */
            <g>
              {/* Bug Legs */}
              <line x1="4" y1="8" x2="0" y2="4" stroke="#f87171" strokeWidth="1.5" strokeLinecap="round" />
              <line x1="20" y1="8" x2="24" y2="4" stroke="#f87171" strokeWidth="1.5" strokeLinecap="round" />
              <line x1="3" y1="13" x2="-1" y2="13" stroke="#f87171" strokeWidth="1.5" strokeLinecap="round" />
              <line x1="21" y1="13" x2="25" y2="13" stroke="#f87171" strokeWidth="1.5" strokeLinecap="round" />
              <line x1="4" y1="18" x2="0" y2="22" stroke="#f87171" strokeWidth="1.5" strokeLinecap="round" />
              <line x1="20" y1="18" x2="24" y2="22" stroke="#f87171" strokeWidth="1.5" strokeLinecap="round" />

              {/* Bug Body & Antennae */}
              <path d="M 9 5 L 6 1" stroke="#f87171" strokeWidth="1.2" strokeLinecap="round" />
              <path d="M 15 5 L 18 1" stroke="#f87171" strokeWidth="1.2" strokeLinecap="round" />
              <ellipse cx="12" cy="7" rx="4" ry="3.5" fill="#dc2626" />
              <ellipse cx="12" cy="14" rx="6" ry="7" fill="#b91c1c" stroke="#fca5a5" strokeWidth="1" />
              <line x1="12" y1="9" x2="12" y2="20" stroke="#fca5a5" strokeWidth="1" />
            </g>
          )}
        </g>

        {/* Small CVSS Pill Overlay in Corner */}
        {node.cvss && (
          <g transform={`translate(${x + 12}, ${y - 18})`}>
            <rect
              x="-8"
              y="-5"
              width="22"
              height="12"
              rx="3"
              fill={isDark ? '#18181b' : '#fee2e2'}
              stroke={isDark ? '#71717a' : '#f87171'}
              strokeWidth="0.8"
            />
            <text
              x="3"
              y="4"
              fill={isDark ? '#fca5a5' : '#991b1b'}
              fontSize="8"
              fontWeight="bold"
              fontFamily="ui-monospace, monospace"
              textAnchor="middle"
            >
              {Number(node.cvss).toFixed(1)}
            </text>
          </g>
        )}

        {/* Bug Name / CVE Identifier */}
        <text
          x={x}
          y={y + 36}
          fill={isFaded ? '#64748b' : isDark ? '#f8fafc' : '#0f172a'}
          fontSize="11"
          fontWeight="600"
          fontFamily="Plus Jakarta Sans, sans-serif"
          textAnchor="middle"
        >
          {name}
        </text>

        {/* Status Micro-text */}
        <text
          x={x}
          y={y + 48}
          fill={isHealed ? (isDark ? '#34d399' : '#047857') : (isDark ? '#f87171' : '#b91c1c')}
          fontSize="9"
          fontWeight="700"
          fontFamily="ui-monospace, monospace"
          textAnchor="middle"
        >
          {isHealed ? 'REMEDIATED' : 'EXPLOITABLE'}
        </text>

        {/* Code Available Pill Indicator */}
        <g transform={`translate(${x}, ${y + 58})`} className="select-none pointer-events-none">
          <rect
            x="-25"
            y="-6"
            width="50"
            height="13"
            rx="3"
            fill={isDark ? '#09090b' : '#fef3c7'}
            stroke={isDark ? '#f59e0b' : '#d97706'}
            strokeWidth="0.8"
            strokeOpacity="0.8"
          />
          <text
            x="0"
            y="3.5"
            fill={isDark ? '#fbbf24' : '#78350f'}
            fontSize="8"
            fontWeight="bold"
            fontFamily="ui-monospace, monospace"
            textAnchor="middle"
          >
            &lt;/&gt; CODE
          </text>
        </g>
      </g>
    );
  }

  // 3. MITIGATION NODES (Cyber Defense Shield & Patch Icon)
  if (label === 'Mitigation') {
    return (
      <g className="mitigation-shield-node">
        {/* Glow */}
        {!isFaded && (
          <circle cx={x} cy={y} r="26" fill="rgba(16, 185, 129, 0.4)" filter="blur(8px)" />
        )}

        {/* Selection Ring */}
        {isSelected && !isFaded && (
          <circle
            cx={x}
            cy={y}
            r="32"
            fill="none"
            stroke="#38bdf8"
            strokeWidth="2"
            strokeDasharray="5 3"
          />
        )}

        {/* Shield Outer Barrier */}
        <path
          d={`
            M ${x} ${y - 25}
            L ${x + 22} ${y - 14}
            V ${y + 5}
            C ${x + 22} ${y + 18} ${x} ${y + 26} ${x} ${y + 26}
            C ${x} ${y + 26} ${x - 22} ${y + 18} ${x - 22} ${y + 5}
            V ${y - 14}
            Z
          `}
          fill={isDark ? '#064e3b' : '#d1fae5'}
          stroke="#10b981"
          strokeWidth={isSelected ? 2.5 : 2}
        />

        {/* Inner Shield Defense Glyph */}
        <g transform={`translate(${x - 11}, ${y - 11})`} style={{ pointerEvents: 'none' }}>
          <path
            d="M 11 3 L 18 6.5 V 12 C 18 16 11 19 11 19 C 11 19 4 16 4 12 V 6.5 Z"
            fill="#059669"
            stroke="#34d399"
            strokeWidth="1"
          />
          {/* Security Checkmark */}
          <path
            d="M 7.5 11 L 10 13.5 L 14.5 8"
            fill="none"
            stroke="#ffffff"
            strokeWidth="2"
            strokeLinecap="round"
            strokeLinejoin="round"
          />
        </g>

        {/* Mitigation Name */}
        <text
          x={x}
          y={y + 38}
          fill={isFaded ? '#64748b' : isDark ? '#f8fafc' : '#0f172a'}
          fontSize="11"
          fontWeight="600"
          fontFamily="Plus Jakarta Sans, sans-serif"
          textAnchor="middle"
        >
          {name}
        </text>
        <text
          x={x}
          y={y + 49}
          fill={isDark ? '#34d399' : '#047857'}
          fontSize="9"
          fontWeight="700"
          fontFamily="ui-monospace, monospace"
          textAnchor="middle"
        >
          ACTIVE DEFENSE
        </text>
      </g>
    );
  }

  // 4. THREAT ACTOR NODES (Hooded Cyber Adversary / APT Emblem)
  if (label === 'ThreatActor') {
    return (
      <g className="threat-actor-node">
        {/* Radar Pulse / Target Grid */}
        {!isFaded && (
          <circle cx={x} cy={y} r="28" fill="rgba(239, 68, 68, 0.3)" filter="blur(8px)" />
        )}

        {/* Selection Ring */}
        {isSelected && !isFaded && (
          <circle cx={x} cy={y} r="32" fill="none" stroke="#38bdf8" strokeWidth="2" strokeDasharray="5 3" />
        )}

        {/* Hexagonal Adversary Frame */}
        <polygon
          points={`
            ${x},${y - 25}
            ${x + 22},${y - 12}
            ${x + 22},${y + 12}
            ${x},${y + 25}
            ${x - 22},${y + 12}
            ${x - 22},${y - 12}
          `}
          fill={isDark ? '#450a0a' : '#fee2e2'}
          stroke="#ef4444"
          strokeWidth={isSelected ? 2.5 : 2}
        />

        {/* Adversary Silhouette / Targeting Reticle Icon */}
        <g transform={`translate(${x - 12}, ${y - 12})`} style={{ pointerEvents: 'none' }}>
          {/* Hood Silhouette */}
          <path
            d="M 12 3 C 7 3 5 8 5 13 C 5 18 7 21 12 21 C 17 21 19 18 19 13 C 19 8 17 3 12 3 Z"
            fill="#7f1d1d"
            stroke="#f87171"
            strokeWidth="1"
          />
          {/* Mask / Visor Eyes */}
          <ellipse cx="9" cy="12" rx="2" ry="1" fill="#fecaca" />
          <ellipse cx="15" cy="12" rx="2" ry="1" fill="#fecaca" />
          {/* Crosshair Target Reticle */}
          <circle cx="12" cy="12" r="10" fill="none" stroke="#ef4444" strokeWidth="0.8" opacity="0.6" strokeDasharray="2 2" />
        </g>

        {/* APT Name */}
        <text
          x={x}
          y={y + 38}
          fill={isFaded ? '#64748b' : isDark ? '#f8fafc' : '#0f172a'}
          fontSize="11"
          fontWeight="700"
          fontFamily="Plus Jakarta Sans, sans-serif"
          textAnchor="middle"
        >
          {name}
        </text>
        <text
          x={x}
          y={y + 49}
          fill={isDark ? '#f87171' : '#b91c1c'}
          fontSize="9"
          fontWeight="700"
          fontFamily="ui-monospace, monospace"
          textAnchor="middle"
        >
          NATION-STATE APT
        </text>
      </g>
    );
  }

  // 5. MALWARE / TOOL NODES (Malicious Binary Payload / Virus Icon)
  if (label === 'Malware') {
    return (
      <g className="malware-node">
        {/* Aura */}
        {!isFaded && (
          <circle cx={x} cy={y} r="26" fill="rgba(168, 85, 247, 0.35)" filter="blur(8px)" />
        )}

        {/* Selection Ring */}
        {isSelected && !isFaded && (
          <circle cx={x} cy={y} r="30" fill="none" stroke="#38bdf8" strokeWidth="2" strokeDasharray="5 3" />
        )}

        {/* Diamond / Lozenge Cyber Token */}
        <polygon
          points={`
            ${x},${y - 24}
            ${x + 22},${y}
            ${x},${y + 24}
            ${x - 22},${y}
          `}
          fill={isDark ? '#3b0764' : '#f3e8ff'}
          stroke="#a855f7"
          strokeWidth={isSelected ? 2.5 : 2}
        />

        {/* Skull / Virus Binary Glyph */}
        <g transform={`translate(${x - 10}, ${y - 10})`} style={{ pointerEvents: 'none' }}>
          <ellipse cx="10" cy="9" rx="7" ry="6" fill="#7e22ce" stroke="#d8b4fe" strokeWidth="1" />
          <circle cx="7.5" cy="8.5" r="1.5" fill="#f5d0fe" />
          <circle cx="12.5" cy="8.5" r="1.5" fill="#f5d0fe" />
          <path d="M 8 13 L 8 16 M 10 13 L 10 16 M 12 13 L 12 16" stroke="#d8b4fe" strokeWidth="1" />
        </g>

        {/* Malware Name */}
        <text
          x={x}
          y={y + 36}
          fill={isFaded ? '#64748b' : isDark ? '#f8fafc' : '#0f172a'}
          fontSize="11"
          fontWeight="600"
          fontFamily="Plus Jakarta Sans, sans-serif"
          textAnchor="middle"
        >
          {name}
        </text>
        <text
          x={x}
          y={y + 47}
          fill={isDark ? '#c084fc' : '#7e22ce'}
          fontSize="9"
          fontWeight="700"
          fontFamily="ui-monospace, monospace"
          textAnchor="middle"
        >
          C2 EXPLOIT TOOL
        </text>
      </g>
    );
  }

  // 6. TECHNIQUE NODES (MITRE ATT&CK TTP Crosshair Icon)
  return (
    <g className="technique-node">
      {/* Selection Ring */}
      {isSelected && !isFaded && (
        <circle cx={x} cy={y} r="28" fill="none" stroke="#38bdf8" strokeWidth="2" strokeDasharray="5 3" />
      )}

      {/* Target Reticle Body */}
      <circle
        cx={x}
        cy={y}
        r="22"
        fill={isDark ? '#1e293b' : '#e2e8f0'}
        stroke="#64748b"
        strokeWidth={isSelected ? 2.5 : 1.5}
      />
      <circle cx={x} cy={y} r="14" fill="none" stroke="#94a3b8" strokeWidth="1" strokeDasharray="2 2" />
      <line x1={x - 20} y1={y} x2={x + 20} y2={y} stroke="#94a3b8" strokeWidth="1" />
      <line x1={x} y1={y - 20} x2={x} y2={y + 20} stroke="#94a3b8" strokeWidth="1" />
      <circle cx={x} cy={y} r="3" fill="#f59e0b" />

      {/* Technique Identifier */}
      <text
        x={x}
        y={y + 34}
        fill={isFaded ? '#64748b' : isDark ? '#f8fafc' : '#0f172a'}
        fontSize="11"
        fontWeight="600"
        fontFamily="Plus Jakarta Sans, sans-serif"
        textAnchor="middle"
      >
        {name}
      </text>
      <text
        x={x}
        y={y + 45}
        fill={isDark ? '#fbbf24' : '#b45309'}
        fontSize="9"
        fontWeight="700"
        fontFamily="ui-monospace, monospace"
        textAnchor="middle"
      >
        MITRE TTP
      </text>
    </g>
  );
};
