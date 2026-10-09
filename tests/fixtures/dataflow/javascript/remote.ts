export const fetchRemote = async (target: string) => {
  const response = await fetch(target);
  return response.text();
};
