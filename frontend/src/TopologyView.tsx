import {
  ArrowUpRight,
  Box,
  CheckCircle2,
  RotateCcw,
  Rows3,
  ShieldAlert,
} from "lucide-react";
import { Canvas, useFrame, useThree } from "@react-three/fiber";
import {
  Grid,
  Html,
  OrbitControls,
  PerspectiveCamera,
  QuadraticBezierLine,
} from "@react-three/drei";
import { Component, useEffect, useMemo, useRef, useState } from "react";
import type { ReactNode } from "react";
import type { Mesh } from "three";
import { MathUtils } from "three";
import type { OrbitControls as OrbitControlsImpl } from "three-stdlib";

import type {
  AlertRecord,
  DashboardData,
  PolicyKey,
  Severity,
} from "./types";

type NodeKind = "principal" | "resource";

interface TopologyNode {
  id: string;
  label: string;
  kind: NodeKind;
  classification: string;
  risk: number;
  events: number;
  primaryAlertId: number;
  position: [number, number, number];
}

interface TopologyEdge {
  id: string;
  source: TopologyNode;
  target: TopologyNode;
  risk: number;
  events: number;
  primaryAlertId: number;
}

interface TopologyGraph {
  nodes: TopologyNode[];
  edges: TopologyEdge[];
}

const titleCase = (value: string) =>
  value
    .replaceAll("_", " ")
    .replace(/\b\w/g, (letter) => letter.toUpperCase());

const riskText = (value: number) =>
  Number(value) < 0.1 ? Number(value).toFixed(3) : Number(value).toFixed(1);

function severityForRisk(risk: number, topOneThreshold: number): Severity {
  if (risk >= 99.8) return "critical";
  if (risk >= topOneThreshold) return "high";
  return "review";
}

function stableHash(value: string) {
  let hash = 2166136261;
  for (let index = 0; index < value.length; index += 1) {
    hash ^= value.charCodeAt(index);
    hash = Math.imul(hash, 16777619);
  }
  return Math.abs(hash);
}

function buildGraph(data: DashboardData, policy: PolicyKey): TopologyGraph {
  const threshold = data.operating_points[policy].threshold;
  const alerts = data.alerts
    .filter((alert) => alert.risk >= threshold)
    .slice(0, 220);

  const entityMap = new Map<string, AlertRecord[]>();
  const resourceMap = new Map<string, AlertRecord[]>();
  for (const alert of alerts) {
    const entityEvents = entityMap.get(alert.entity) ?? [];
    entityEvents.push(alert);
    entityMap.set(alert.entity, entityEvents);

    const resourceEvents = resourceMap.get(alert.resource) ?? [];
    resourceEvents.push(alert);
    resourceMap.set(alert.resource, resourceEvents);
  }

  const selectedEntities = [...entityMap.entries()]
    .sort(
      ([, left], [, right]) =>
        Math.max(...right.map((event) => event.risk)) -
          Math.max(...left.map((event) => event.risk)) ||
        right.length - left.length,
    )
    .slice(0, 34);
  const selectedResources = [...resourceMap.entries()]
    .sort(([, left], [, right]) => right.length - left.length)
    .slice(0, 28);

  const entityNodes = new Map<string, TopologyNode>();
  let entityOrdinal = 0;
  for (const [label, events] of selectedEntities) {
    const primary = [...events].sort((a, b) => b.risk - a.risk)[0];
    const classification = primary.classification;
    const angle =
      (entityOrdinal / Math.max(1, selectedEntities.length)) * Math.PI * 2 +
      Math.PI / 2 +
      ((stableHash(label) % 21) - 10) * 0.012;
    const radius = 5.1 + (stableHash(`${label}-radius`) % 19) / 32;
    const y = ((stableHash(`${label}-y`) % 100) / 100 - 0.5) * 3.8;
    entityNodes.set(label, {
      id: `entity:${label}`,
      label,
      kind: "principal",
      classification,
      risk: primary.risk,
      events: events.length,
      primaryAlertId: primary.id,
      position: [
        Math.cos(angle) * radius,
        y,
        Math.sin(angle) * radius,
      ],
    });
    entityOrdinal += 1;
  }

  const resourceNodes = new Map<string, TopologyNode>();
  selectedResources.forEach(([label, events], index) => {
    const primary = [...events].sort((a, b) => b.risk - a.risk)[0];
    const angle =
      (index / Math.max(1, selectedResources.length)) * Math.PI * 2 +
      ((stableHash(label) % 17) - 8) * 0.018;
    const radius = 2.55 + (index % 4) * 0.34;
    const y = ((stableHash(`${label}-resource-y`) % 100) / 100 - 0.5) * 2.4;
    resourceNodes.set(label, {
      id: `resource:${label}`,
      label,
      kind: "resource",
      classification: primary.classification,
      risk: primary.risk,
      events: events.length,
      primaryAlertId: primary.id,
      position: [
        Math.cos(angle) * radius,
        y,
        Math.sin(angle) * radius,
      ],
    });
  });

  const edgeMap = new Map<string, TopologyEdge>();
  for (const alert of alerts) {
    const source = entityNodes.get(alert.entity);
    const target = resourceNodes.get(alert.resource);
    if (!source || !target) continue;
    const id = `${source.id}->${target.id}`;
    const existing = edgeMap.get(id);
    if (existing) {
      existing.events += 1;
      if (alert.risk > existing.risk) existing.primaryAlertId = alert.id;
      existing.risk = Math.max(existing.risk, alert.risk);
    } else {
      edgeMap.set(id, {
        id,
        source,
        target,
        risk: alert.risk,
        events: 1,
        primaryAlertId: alert.id,
      });
    }
  }

  return {
    nodes: [...entityNodes.values(), ...resourceNodes.values()],
    edges: [...edgeMap.values()].slice(0, 105),
  };
}

function SignalPacket({
  edge,
  index,
  motionEnabled,
}: {
  edge: TopologyEdge;
  index: number;
  motionEnabled: boolean;
}) {
  const mesh = useRef<Mesh>(null);
  const color = edge.risk >= 99.8 ? "#D92D20" : "#3B82F6";
  const speed = 0.075 + (index % 5) * 0.012;
  const offset = ((stableHash(edge.id) % 100) / 100 + index * 0.17) % 1;

  useFrame((state) => {
    if (!mesh.current) return;
    const progress = motionEnabled
      ? (state.clock.elapsedTime * speed + offset) % 1
      : offset;
    const eased = progress * progress * (3 - 2 * progress);
    mesh.current.position.set(
      MathUtils.lerp(edge.source.position[0], edge.target.position[0], eased),
      MathUtils.lerp(edge.source.position[1], edge.target.position[1], eased),
      MathUtils.lerp(edge.source.position[2], edge.target.position[2], eased),
    );
    const pulse = 0.85 + Math.sin(progress * Math.PI) * 0.35;
    mesh.current.scale.setScalar(pulse);
  });

  return (
    <mesh ref={mesh}>
      <sphereGeometry args={[edge.risk >= 99.8 ? 0.045 : 0.032, 10, 10]} />
      <meshBasicMaterial color={color} />
    </mesh>
  );
}

function NetworkNode({
  node,
  selected,
  hovered,
  onSelect,
  onHover,
  topOneThreshold,
}: {
  node: TopologyNode;
  selected: boolean;
  hovered: boolean;
  onSelect: (node: TopologyNode) => void;
  onHover: (node: TopologyNode | null) => void;
  topOneThreshold: number;
}) {
  const mesh = useRef<Mesh>(null);
  const halo = useRef<Mesh>(null);
  const severity = severityForRisk(node.risk, topOneThreshold);
  const color =
    severity === "critical"
      ? "#D92D20"
      : severity === "high"
        ? "#F79009"
        : "#667085";
  const baseScale =
    node.kind === "principal"
      ? 0.16 + Math.min(0.08, node.events * 0.004)
      : 0.13 + Math.min(0.06, node.events * 0.003);

  useFrame((_, delta) => {
    if (mesh.current) {
      const target = baseScale * (hovered ? 1.38 : selected ? 1.2 : 1);
      const current = mesh.current.scale.x;
      const next = MathUtils.damp(current, target, 9, delta);
      mesh.current.scale.setScalar(next);
    }
  });

  return (
    <group position={node.position}>
      <mesh
        ref={mesh}
        scale={baseScale}
        onClick={(event) => {
          event.stopPropagation();
          onSelect(node);
        }}
        onPointerOver={(event) => {
          event.stopPropagation();
          document.body.style.cursor = "pointer";
          onHover(node);
        }}
        onPointerOut={() => {
          document.body.style.cursor = "";
          onHover(null);
        }}
      >
        {node.kind === "principal" ? (
          <icosahedronGeometry args={[1, 1]} />
        ) : (
          <octahedronGeometry args={[0.92, 0]} />
        )}
        <meshStandardMaterial
          color={selected ? "#3B82F6" : color}
          emissive="#000000"
          emissiveIntensity={0}
          metalness={0.24}
          roughness={0.62}
          transparent
          opacity={node.kind === "principal" ? 0.98 : 0.82}
        />
      </mesh>

      {selected && (
        <mesh ref={halo} rotation={[Math.PI / 2, 0, 0]}>
          <torusGeometry
            args={[
              baseScale * 1.65,
              0.018,
              6,
              48,
            ]}
          />
          <meshBasicMaterial
            color="#3B82F6"
            transparent
            opacity={0.85}
          />
        </mesh>
      )}

      {hovered && (
        <Html center distanceFactor={10} zIndexRange={[30, 0]}>
          <div className="topology-node-label">
            <span>{node.kind}</span>
            <strong>{node.label}</strong>
            <small>
              {riskText(node.risk)} risk / {node.events} events
            </small>
          </div>
        </Html>
      )}
    </group>
  );
}

function TopologyScene({
  graph,
  selectedNode,
  onSelect,
  resetVersion,
  topOneThreshold,
  motionEnabled,
}: {
  graph: TopologyGraph;
  selectedNode: TopologyNode | null;
  onSelect: (node: TopologyNode) => void;
  resetVersion: number;
  topOneThreshold: number;
  motionEnabled: boolean;
}) {
  const controls = useRef<OrbitControlsImpl>(null);
  const [hoveredNode, setHoveredNode] = useState<TopologyNode | null>(null);
  const { size } = useThree();
  const narrowViewport = size.width < 700;

  useEffect(() => {
    controls.current?.reset();
  }, [resetVersion]);

  const animatedEdges = useMemo(
    () =>
      selectedNode
        ? graph.edges
            .filter(
              (edge) =>
                edge.source.id === selectedNode.id ||
                edge.target.id === selectedNode.id,
            )
            .sort((left, right) => right.risk - left.risk)
            .slice(0, 8)
        : [],
    [graph.edges, selectedNode],
  );

  return (
    <>
      <color attach="background" args={["#0F172A"]} />
      <fog attach="fog" args={["#0F172A", 9, 22]} />
      <PerspectiveCamera
        makeDefault
        position={narrowViewport ? [-0.7, 3.2, 22.5] : [-0.7, 3.5, 11.7]}
        fov={narrowViewport ? 58 : 44}
      />
      <ambientLight intensity={1.15} />
      <directionalLight position={[6, 9, 7]} intensity={1.55} color="#DDE5EF" />
      <pointLight position={[-7, -2, 3]} intensity={0.8} color="#8B96A8" />

      <Grid
        position={[0, -3.05, 0]}
        args={[28, 28]}
        cellSize={0.55}
        cellThickness={0.5}
        cellColor="#263244"
        sectionSize={3.3}
        sectionThickness={0.8}
        sectionColor="#344054"
        fadeDistance={18}
        fadeStrength={1.6}
        infiniteGrid
      />

      <group position={[-0.7, 0, 0]}>
        {graph.edges.map((edge) => {
          const active =
            selectedNode?.id === edge.source.id ||
            selectedNode?.id === edge.target.id;
          const midpoint: [number, number, number] = [
            (edge.source.position[0] + edge.target.position[0]) / 2,
            (edge.source.position[1] + edge.target.position[1]) / 2 +
              0.22 +
              (stableHash(edge.id) % 4) * 0.05,
            (edge.source.position[2] + edge.target.position[2]) / 2,
          ];
          return (
          <QuadraticBezierLine
            key={edge.id}
            start={edge.source.position}
            end={edge.target.position}
            mid={midpoint}
            color={active ? "#3B82F6" : "#475467"}
            lineWidth={active ? 1.35 : 0.5}
            transparent
            opacity={active ? 0.72 : 0.18}
            depthWrite={false}
          />
          );
        })}

        {animatedEdges.map((edge, index) => (
          <SignalPacket
            key={`packet:${edge.id}`}
            edge={edge}
            index={index}
            motionEnabled={motionEnabled}
          />
        ))}

        {graph.nodes.map((node) => (
          <NetworkNode
            key={node.id}
            node={node}
            selected={selectedNode?.id === node.id}
            hovered={hoveredNode?.id === node.id}
            onSelect={onSelect}
            onHover={setHoveredNode}
            topOneThreshold={topOneThreshold}
          />
        ))}
      </group>

      <OrbitControls
        ref={controls}
        makeDefault
        enableDamping
        dampingFactor={0.065}
        minDistance={narrowViewport ? 14 : 6.7}
        maxDistance={narrowViewport ? 28 : 17}
        maxPolarAngle={Math.PI * 0.78}
        minPolarAngle={Math.PI * 0.17}
        target={[-0.7, 0, 0]}
      />
    </>
  );
}

function TopologyStat({
  label,
  value,
}: {
  label: string;
  value: string | number;
}) {
  return (
    <div className="topology-stat">
      <span>{label}</span>
      <strong>{value}</strong>
    </div>
  );
}

class GraphicsBoundary extends Component<{children: ReactNode; onUnavailable: () => void}, {failed: boolean}> {
  state = {failed:false};
  static getDerivedStateFromError() { return {failed:true}; }
  componentDidCatch() { this.props.onUnavailable(); }
  render() { return this.state.failed ? null : this.props.children; }
}

export default function TopologyView({
  data,
  policy,
  onInvestigate,
}: {
  data: DashboardData;
  policy: PolicyKey;
  onInvestigate: (alertId: number) => void;
}) {
  const graph = useMemo(() => buildGraph(data, policy), [data, policy]);
  const [selectedNode, setSelectedNode] = useState<TopologyNode | null>(
    graph.nodes[0] ?? null,
  );
  const reduceMotion = useMemo(
    () =>
      typeof window !== "undefined" &&
      window.matchMedia("(prefers-reduced-motion: reduce)").matches,
    [],
  );
  const [resetVersion, setResetVersion] = useState(0);
  const [tableMode, setTableMode] = useState(false);
  const [graphicsFailed, setGraphicsFailed] = useState(false);
  const useTable = () => { setGraphicsFailed(true); setTableMode(true); };
  const topOneThreshold = data.operating_points.top_1pct.threshold;

  useEffect(() => {
    setSelectedNode(graph.nodes[0] ?? null);
  }, [graph]);

  const criticalNodes = graph.nodes.filter(
    (node) => node.risk >= 99.8,
  ).length;
  const hottestNode = [...graph.nodes].sort((a, b) => b.risk - a.risk)[0];

  if (tableMode) return <main className="live-workspace view-enter">
    <section className="live-intro"><div><div className="eyebrow">STORED SYNTHETIC ACCESS-LOG RESULTS</div><h2>Entity-resource connections</h2>
      <p>{graph.nodes.length} principals and resources · {graph.edges.length} observed links at the selected policy threshold.</p>
      {graphicsFailed && <p>3D graphics are unavailable on this device. All connections remain accessible in this table.</p>}</div>
      {!graphicsFailed && <button onClick={() => setTableMode(false)}>Show 3D topology</button>}</section>
    <section className="live-panel live-events"><h3>Observed connections</h3><div className="live-table-scroll"><table><thead><tr><th>Principal</th><th>Resource</th><th>Events</th><th>Risk</th><th>Evidence</th></tr></thead>
      <tbody>{graph.edges.map(edge => <tr key={edge.id}><td>{edge.source.label}</td><td>{edge.target.label}</td><td>{edge.events}</td><td>{riskText(edge.risk)}</td><td><button onClick={() => onInvestigate(edge.primaryAlertId)}>Investigate {edge.source.label}</button></td></tr>)}</tbody></table></div></section>
  </main>;

  return (
    <main className="topology-view view-enter">
      <div className="topology-canvas" data-testid="topology-canvas">
        <GraphicsBoundary onUnavailable={useTable}><Canvas
          dpr={[1, 1.65]}
          gl={{
            antialias: true,
            alpha: false,
            powerPreference: "high-performance",
            preserveDrawingBuffer: true,
          }}
          onPointerMissed={() => setSelectedNode(null)}
        >
          <TopologyScene
            graph={graph}
            selectedNode={selectedNode}
            onSelect={setSelectedNode}
            resetVersion={resetVersion}
            topOneThreshold={topOneThreshold}
            motionEnabled={!reduceMotion}
          />
        </Canvas></GraphicsBoundary>
      </div>

      <header className="topology-heading">
        <div className="section-kicker">Behaviour graph / selected policy</div>
        <h2>Entity-resource topology</h2>
        <p>
          {titleCase(policy.replace("pct", "%"))} threshold{" "}
          {riskText(data.operating_points[policy].threshold)}
        </p>
      </header>

      <div className="topology-stats" aria-label="Topology statistics">
        <TopologyStat label="Principals + resources" value={graph.nodes.length} />
        <TopologyStat label="Observed links" value={graph.edges.length} />
        <TopologyStat label="Critical nodes" value={criticalNodes} />
        <TopologyStat label="Highest risk" value={riskText(hottestNode?.risk ?? 0)} />
      </div>

      <div className="topology-controls">
        <button type="button" onClick={() => setTableMode(true)} aria-label="Show topology table" title="Show topology table"><Rows3 size={16}/></button>
        <button
          type="button"
          onClick={() => setResetVersion((value) => value + 1)}
          aria-label="Reset topology camera"
          title="Reset topology camera"
        >
          <RotateCcw size={16} />
        </button>
      </div>

      <aside className="topology-legend" aria-label="Attack family legend">
        <div className="legend-title">
          <ShieldAlert size={14} />
          Risk state
        </div>
        <div className="topology-legend-row">
          <span style={{ background: "#D92D20" }} />
          <label>Critical</label>
        </div>
        <div className="topology-legend-row">
          <span style={{ background: "#F79009" }} />
          <label>High</label>
        </div>
        <div className="topology-legend-row">
          <span style={{ background: "#667085" }} />
          <label>Review</label>
        </div>
        <div className="topology-legend-row">
          <span style={{ background: "#3B82F6" }} />
          <label>Selected path</label>
        </div>
        <div className="legend-divider" />
        <div className="node-shape-row">
          <span className="shape principal" />
          <label>Principal</label>
          <span className="shape resource" />
          <label>Resource</label>
        </div>
      </aside>

      {selectedNode && (
        <aside className="topology-selection">
          <div
            className="selection-accent"
            style={{
              background: "#3B82F6",
            }}
          />
          <div className="selection-icon">
            {selectedNode.kind === "principal" ? (
              <ShieldAlert size={19} />
            ) : (
              <Box size={19} />
            )}
          </div>
          <div className="selection-copy">
            <span>
              {selectedNode.kind} / {titleCase(selectedNode.classification)}
            </span>
            <strong>{selectedNode.label}</strong>
            <small>
              Risk {riskText(selectedNode.risk)} / {selectedNode.events} observed
              events
            </small>
          </div>
          <div className="selection-state">
            <CheckCircle2 size={14} />
            selected
          </div>
          <button
            type="button"
            onClick={() => onInvestigate(selectedNode.primaryAlertId)}
          >
            Investigate
            <ArrowUpRight size={15} />
          </button>
        </aside>
      )}

    </main>
  );
}
