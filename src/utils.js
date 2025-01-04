export function selectFirstMatch(peerArray, preferences){
   for (const preference of preferences) {
      if (peerArray.includes(preference)) {
        return preference; // Return the first match
      }
    }
    return null; // Return null if no match is found
}

export function selectKeyExchange(keyShareEntries, preferences){
   const entries = [...keyShareEntries.values()]
   const groups = new Set(entries.map(e=>e.group.name));
   
   const selectedGroup = groups.intersection(preferences).values().next().value;//selectFirstMatch(groups, preferences);
   //return selectedGroup;
   return entries.filter((item) => {
      return item.group.name == selectedGroup
   })[0]
}